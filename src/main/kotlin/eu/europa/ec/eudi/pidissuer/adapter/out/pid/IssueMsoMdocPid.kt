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

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.util.*

val PidMsoMdocScope: Scope = Scope("${PID_DOCTYPE}_${MSO_MDOC_FORMAT.value}")

val PidMsoMdocNamespace: MsoNameSpace = pidNameSpace(1)

val GivenNameAttribute = AttributeDetails(
    name = "given_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Current First Names"),
)
val FamilyNameAttribute = AttributeDetails(
    name = "family_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Current Family Name"),
)
val BirthDateAttribute = AttributeDetails(
    name = "birth_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date of Birth"),
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
val GenderAttribute = AttributeDetails(
    name = "gender",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "PID User’s gender, using a value as defined in ISO/IEC 5218."),
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
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code, representing the nationality of the PID User."),
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
    display = mapOf(Locale.ENGLISH to "The country, state, and city where the PID User was born."),
)
val BirthCountryAttribute = AttributeDetails(
    name = "birth_country",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The country where the PID User was born, as an Alpha-2 country code."),
)
val BirthStateAttribute = AttributeDetails(
    name = "birth_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born. "),
)
val BirthCityAttribute = AttributeDetails(
    name = "birth_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User was born. "),
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
        Locale.ENGLISH to "he country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1.",
    ),
)
val ResidenceStateAttribute = AttributeDetails(
    name = "resident_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User currently resides"),
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
    display = mapOf(Locale.ENGLISH to "The name of the street where the PID User currently resides"),
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
val AdministrativeNumberAttribute = AttributeDetails(
    name = "document_number",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "A number for the PID, assigned by the PID Provider."),
)
val IssuingCountryAttribute = AttributeDetails(
    name = "issuing_country",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider’s country or territory."),
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
private val pidAttributes = PidMsoMdocNamespace to listOf(
    FamilyNameAttribute,
    GivenNameAttribute,
    BirthDateAttribute,
    AgeOver18Attribute,
    AgeBirthYearAttribute,
    AgeInYearsAttribute,
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

val PidMsoMdocV1: MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(PidMsoMdocScope.value),
        docType = pidDocType(1),
        display = pidDisplay,
        msoClaims = mapOf(pidAttributes),
        cryptographicBindingMethodsSupported = emptySet(),
        credentialSigningAlgorithmsSupported = emptySet(),
        scope = PidMsoMdocScope,
        proofTypesSupported = ProofTypesSupported(nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.ES256)))),
    )

//
// Meta
//

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

/**
 * Service for issuing PID MsoMdoc credential
 */
class IssueMsoMdocPid(
    credentialIssuerId: CredentialIssuerId,
    private val getPidData: GetPidData,
    private val encodePidInCbor: EncodePidInCbor,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val clock: Clock,
    private val storeIssuedCredential: StoreIssuedCredential,
) : IssueSpecificCredential<JsonElement> {

    private val log = LoggerFactory.getLogger(IssueMsoMdocPid::class.java)

    private val validateProof = ValidateProof(credentialIssuerId)
    override val supportedCredential: MsoMdocCredentialConfiguration
        get() = PidMsoMdocV1
    override val publicKey: JWK? = null

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val cbor = encodePidInCbor(pid, pidMetaData, holderPubKey.await()).also {
            log.info("Issued $it")
        }

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null
        storeIssuedCredential(
            IssuedCredential(
                format = MSO_MDOC_FORMAT,
                type = supportedCredential.docType,
                holder = with(pid) {
                    "${familyName.value} ${givenName.value}"
                },
                holderPublicKey = holderPubKey.await().toPublicJWK(),
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(JsonPrimitive(cbor), notificationId)
            .also {
                log.info("Successfully issued PID")
                log.debug("Issued PID data {}", it)
            }
    }

    context(Raise<IssueCredentialError>)
    @Suppress("DuplicatedCode")
    private fun holderPubKey(request: CredentialRequest, expectedCNonce: CNonce): ECKey {
        fun ecKeyOrFail(provider: () -> ECKey) = try {
            provider.invoke()
        } catch (t: Throwable) {
            raise(InvalidProof("Only EC Key is supported"))
        }
        return when (val key = validateProof(request.unvalidatedProof, expectedCNonce, supportedCredential)) {
            is CredentialKey.DIDUrl -> ecKeyOrFail { key.jwk.toECKey() }
            is CredentialKey.Jwk -> ecKeyOrFail { key.value.toECKey() }
            is CredentialKey.X5c -> ecKeyOrFail { ECKey.parse(key.certificate) }
        }
    }
}
