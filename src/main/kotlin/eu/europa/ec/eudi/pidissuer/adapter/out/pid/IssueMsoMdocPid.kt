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

val GivenNameAttribute = AttributeDetails(
    name = "given_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Current first name(s), including middle name(s), of the PID User."),
)
val FamilyNameAttribute = AttributeDetails(
    name = "family_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Current last name(s) or surname(s) of the PID User."),
)
val BirthDateAttribute = AttributeDetails(
    name = "birth_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Day, month, and year on which the PID User was born."),
)
val FamilyNameBirthAttribute = AttributeDetails(
    name = "family_name_birth",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
)
val GivenNameBirthAttribute = AttributeDetails(
    name = "given_name_birth",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
)
val SexAttribute = AttributeDetails(
    name = "sex",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "PID User's sex, using a value as defined in ISO/IEC 5218."),
)
val AgeOver18Attribute = AttributeDetails(
    name = "age_over_18",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Attesting whether the PID User is currently an adult (true) or a minor (false)."),
)
val AgeBirthYearAttribute = AttributeDetails(
    name = "age_birth_year",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The year when the PID User was born."),
)
val AgeInYearsAttribute = AttributeDetails(
    name = "age_in_years",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The current age of the PID User in years."),
)
val NationalityAttribute = AttributeDetails(
    name = "nationality",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code as specified in ISO 3166-1, representing the nationality of the PID User."),
)
val IssuanceDateAttribute = AttributeDetails(
    name = "issuance_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date (and possibly time) when the PID was issued."),
)
val ExpiryDateAttribute = AttributeDetails(
    name = "expiry_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date (and possibly time) when the PID will expire."),
)
val IssuingAuthorityAttribute = AttributeDetails(
    name = "issuing_authority",
    mandatory = true,
    display = mapOf(
        Locale.ENGLISH to "Name of the administrative authority that has issued this PID instance, " +
            "or the ISO 3166 Alpha-2 country code of the respective Member State if there is " +
            "no separate authority authorized to issue PIDs.",
    ),
)
val BirthPlaceAttribute = AttributeDetails(
    name = "birth_place",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born."),
)
val BirthCountryAttribute = AttributeDetails(
    name = "birth_country",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The country where the PID User was born, as an Alpha-2 country code as specified in ISO 3166-1."),
)
val BirthStateAttribute = AttributeDetails(
    name = "birth_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born."),
)
val BirthCityAttribute = AttributeDetails(
    name = "birth_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User was born."),
)
val ResidenceAddressAttribute = AttributeDetails(
    name = "resident_address",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "The full address of the place where the PID User currently resides and/or " +
            "can be contacted (street name, house number, city etc.).",
    ),
)
val ResidenceCountryAttribute = AttributeDetails(
    name = "resident_country",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "The country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1.",
    ),
)
val ResidenceStateAttribute = AttributeDetails(
    name = "resident_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User currently resides."),
)
val ResidenceCityAttribute = AttributeDetails(
    name = "resident_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User currently resides."),
)
val ResidencePostalCodeAttribute = AttributeDetails(
    name = "resident_postal_code",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Postal code of the place where the PID User currently resides."),
)
val ResidenceStreetAttribute = AttributeDetails(
    name = "resident_street",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The name of the street where the PID User currently resides."),
)
val ResidenceHouseNumberAttribute = AttributeDetails(
    name = "resident_house_number",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The house number where the PID User currently resides, including any affix or suffix."),
)
val DocumentNumberAttribute = AttributeDetails(
    name = "document_number",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "A number for the PID, assigned by the PID Provider."),
)
val PersonalAdministrativeNumberAttribute = AttributeDetails(
    name = "personal_administrative_number",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "A number assigned by the PID Provider for audit control or other purposes."),
)
val IssuingCountryAttribute = AttributeDetails(
    name = "issuing_country",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory."),
)
val IssuingJurisdictionAttribute = AttributeDetails(
    name = "issuing_jurisdiction",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "Country subdivision code of the jurisdiction that issued the PID, " +
            "as defined in ISO 3166-2:2020, Clause 8. The first part of the code SHALL be the same " +
            "as the value for issuing_country.",
    ),
)
val PortraitAttribute = AttributeDetails(
    name = "portrait",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "Facial image of the PID user compliant with ISO 19794-5 or ISO 39794 specifications.",
    ),
)
val EmailAddressAttribute = AttributeDetails(
    name = "email_address",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "Electronic mail address of the PID User to whom the person identification data relates, " +
            "* in conformance with [RFC 5322].",
    ),
)
val MobilePhoneNumberAttribute = AttributeDetails(
    name = "mobile_phone_number",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "Mobile telephone number of the User to whom the person identification data relates, " +
            "starting with the '+' symbol as the international code prefix and the country code, followed " +
            "by numbers only.",
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
    SexAttribute,
    NationalityAttribute,
    IssuanceDateAttribute,
    ExpiryDateAttribute,
    IssuingAuthorityAttribute,
    DocumentNumberAttribute,
    PersonalAdministrativeNumberAttribute,
    IssuingCountryAttribute,
    IssuingJurisdictionAttribute,
    PortraitAttribute,
    EmailAddressAttribute,
    MobilePhoneNumberAttribute,
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
        msoClaims = mapOf(pidAttributes),
        cryptographicBindingMethodsSupported = emptySet(),
        credentialSigningAlgorithmsSupported = emptySet(),
        scope = PidMsoMdocScope,
        proofTypesSupported = ProofTypesSupported(
            nonEmptySetOf(
                ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.ES256)),
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
