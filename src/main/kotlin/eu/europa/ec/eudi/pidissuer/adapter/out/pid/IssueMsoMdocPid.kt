/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import arrow.core.Either
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.jwkExtensions
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.util.*

val PidMsoMdocScope: Scope = Scope("eu.europa.ec.eudi.pid_mso_mdoc")

val PidMsoMdocNamespace: MsoNameSpace = pidNameSpace(1)

private fun pidV1ClaimPath(name: String): ClaimPath = ClaimPath.msoMDoc(PidMsoMdocNamespace, name)

val GivenNameAttribute = AttributeDetails(
    path = pidV1ClaimPath("given_name"),
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Current first name(s), including middle name(s), of the PID User."),
)
val FamilyNameAttribute = AttributeDetails(
    path = pidV1ClaimPath("family_name"),
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Current last name(s) or surname(s) of the PID User."),
)
val BirthDateAttribute = AttributeDetails(
    path = pidV1ClaimPath("birth_date"),
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Day, month, and year on which the PID User was born."),
)
val FamilyNameBirthAttribute = AttributeDetails(
    path = pidV1ClaimPath("family_name_birth"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
)
val GivenNameBirthAttribute = AttributeDetails(
    path = pidV1ClaimPath("given_name_birth"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
)
val GenderAttribute = AttributeDetails(
    path = pidV1ClaimPath("gender"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "PID User's gender, using a value as defined in ISO/IEC 5218."),
)
val AgeOver18Attribute = AttributeDetails(
    path = pidV1ClaimPath("age_over_18"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Attesting whether the PID User is currently an adult (true) or a minor (false)."),
)
val AgeBirthYearAttribute = AttributeDetails(
    path = pidV1ClaimPath("age_birth_year"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The year when the PID User was born."),
)
val AgeInYearsAttribute = AttributeDetails(
    path = pidV1ClaimPath("age_in_years"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The current age of the PID User in years."),
)
val NationalityAttribute = AttributeDetails(
    path = pidV1ClaimPath("nationality"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code as specified in ISO 3166-1, representing the nationality of the PID User."),
)
val IssuanceDateAttribute = AttributeDetails(
    path = pidV1ClaimPath("issuance_date"),
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date (and possibly time) when the PID was issued."),
)
val ExpiryDateAttribute = AttributeDetails(
    path = pidV1ClaimPath("expiry_date"),
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date (and possibly time) when the PID will expire."),
)
val IssuingAuthorityAttribute = AttributeDetails(
    path = pidV1ClaimPath("issuing_authority"),
    mandatory = true,
    display = mapOf(
        Locale.ENGLISH to "Name of the administrative authority that has issued this PID instance, " +
            "or the ISO 3166 Alpha-2 country code of the respective Member State if there is " +
            "no separate authority authorized to issue PIDs.",
    ),
)
val BirthPlaceAttribute = AttributeDetails(
    path = pidV1ClaimPath("birth_place"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born."),
)
val BirthCountryAttribute = AttributeDetails(
    path = pidV1ClaimPath("birth_country"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The country where the PID User was born, as an Alpha-2 country code as specified in ISO 3166-1."),
)
val BirthStateAttribute = AttributeDetails(
    path = pidV1ClaimPath("birth_state"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born."),
)
val BirthCityAttribute = AttributeDetails(
    path = pidV1ClaimPath("birth_city"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User was born."),
)
val ResidenceAddressAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_address"),
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "The full address of the place where the PID User currently resides and/or " +
            "can be contacted (street name, house number, city etc.).",
    ),
)
val ResidenceCountryAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_country"),
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "The country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1.",
    ),
)
val ResidenceStateAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_state"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User currently resides."),
)
val ResidenceCityAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_city"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User currently resides."),
)
val ResidencePostalCodeAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_postal_code"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Postal code of the place where the PID User currently resides."),
)
val ResidenceStreetAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_street"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The name of the street where the PID User currently resides."),
)
val ResidenceHouseNumberAttribute = AttributeDetails(
    path = pidV1ClaimPath("resident_house_number"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The house number where the PID User currently resides, including any affix or suffix."),
)
val DocumentNumberAttribute = AttributeDetails(
    path = pidV1ClaimPath("document_number"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "A number for the PID, assigned by the PID Provider."),
)
val AdministrativeNumberAttribute = AttributeDetails(
    path = pidV1ClaimPath("administrative_number"),
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "A number assigned by the PID Provider for audit control or other purposes."),
)
val IssuingCountryAttribute = AttributeDetails(
    path = pidV1ClaimPath("issuing_country"),
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory."),
)
val IssuingJurisdictionAttribute = AttributeDetails(
    path = pidV1ClaimPath("issuing_jurisdiction"),
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "Country subdivision code of the jurisdiction that issued the PID, " +
            "as defined in ISO 3166-2:2020, Clause 8. The first part of the code SHALL be the same " +
            "as the value for issuing_country.",
    ),
)

private val pidAttributes = PidMsoMdocNamespace to listOf(
    FamilyNameAttribute,
    GivenNameAttribute,
    BirthDateAttribute,
    AgeOver18Attribute,
    AgeInYearsAttribute,
    AgeBirthYearAttribute,
    FamilyNameBirthAttribute,
    GivenNameBirthAttribute,
    BirthPlaceAttribute,
    BirthCountryAttribute,
    BirthStateAttribute,
    BirthCityAttribute,
    ResidenceAddressAttribute,
    ResidenceCountryAttribute,
    ResidenceStateAttribute,
    ResidenceCityAttribute,
    ResidencePostalCodeAttribute,
    ResidenceStreetAttribute,
    ResidenceHouseNumberAttribute,
    GenderAttribute,
    NationalityAttribute,
    IssuanceDateAttribute,
    ExpiryDateAttribute,
    IssuingAuthorityAttribute,
    DocumentNumberAttribute,
    AdministrativeNumberAttribute,
    IssuingCountryAttribute,
    IssuingJurisdictionAttribute,
)

private const val PID_DOCTYPE = "eu.europa.ec.eudi.pid"

private fun pidDocType(v: Int?): String =
    if (v == null) PID_DOCTYPE
    else "$PID_DOCTYPE.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

val PidMsoMdocV1: MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(PidMsoMdocScope.value),
        docType = pidDocType(1),
        display = pidDisplay,
        msoClaims = MsoClaims(mapOf(pidAttributes)),
        cryptographicBindingMethodsSupported = emptySet(),
        credentialSigningAlgorithmsSupported = emptySet(),
        scope = PidMsoMdocScope,
        proofTypesSupported = ProofTypesSupported(
            nonEmptySetOf(
                ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.ES256), KeyAttestation.NotRequired),
            ),
        ),
        policy = MsoMdocPolicy(oneTimeUse = true),
    )

/**
 * Service for issuing PID MsoMdoc credential
 */
internal class IssueMsoMdocPid(
    private val validateProofs: ValidateProofs,
    private val getPidData: GetPidData,
    private val encodePidInCbor: EncodePidInCbor,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val clock: Clock,
    private val storeIssuedCredentials: StoreIssuedCredentials,
) : IssueSpecificCredential {

    private val log = LoggerFactory.getLogger(IssueMsoMdocPid::class.java)

    override val supportedCredential: MsoMdocCredentialConfiguration
        get() = PidMsoMdocV1
    override val publicKey: JWK? = null

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = coroutineScope {
        either {
            log.info("Handling issuance request ...")
            val holderPubKeys = with(jwkExtensions()) {
                validateProofs(request.unvalidatedProofs, supportedCredential, clock.instant())
                    .bind()
                    .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
            }

            val pidData = async { getPidData(authorizationContext) }
            val notificationId =
                if (notificationsEnabled) generateNotificationId()
                else null

            val (pid, pidMetaData) = pidData.await().bind()
            val issuedCredentials = holderPubKeys.map { holderKey ->
                val cbor = encodePidInCbor(pid, pidMetaData, holderKey).also {
                    log.info("Issued $it")
                }
                cbor to holderKey.toPublicJWK()
            }.toNonEmptyListOrNull()
            ensureNotNull(issuedCredentials) {
                IssueCredentialError.Unexpected("Unable to issue PID")
            }

            storeIssuedCredentials(
                IssuedCredentials(
                    format = MSO_MDOC_FORMAT,
                    type = supportedCredential.docType,
                    holder = with(pid) {
                        "${familyName.value} ${givenName.value}"
                    },
                    holderPublicKeys = issuedCredentials.map { it.second },
                    issuedAt = clock.instant(),
                    notificationId = notificationId,
                ),
            )

            CredentialResponse.Issued(issuedCredentials.map { JsonPrimitive(it.first) }, notificationId)
                .also {
                    log.info("Successfully issued PIDs")
                    log.debug("Issued PIDs data {}", it)
                }
        }
    }
}
