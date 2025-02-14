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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

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
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.util.*

val MobileDrivingLicenceV1Scope: Scope = Scope(mdlDocType(1u))

val MobileDrivingLicenceV1Namespace: MsoNameSpace = mdlNamespace(1u)

val FamilyNameAttribute = AttributeDetails(
    name = "family_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Family Name(s)"),
)
val GivenNameAttribute = AttributeDetails(
    name = "given_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Given Name(s)"),
)
val BirthDateAttribute = AttributeDetails(
    name = "birth_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Birth Date"),
)
val IssueDateAttribute = AttributeDetails(
    name = "issue_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Issuance Date"),
)
val ExpiryDateAttribute = AttributeDetails(
    name = "expiry_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Expiry Date"),
)
val PortraitAttribute = AttributeDetails(
    name = "portrait",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Portrait Image"),
)
val PortraitCaptureDateAttribute = AttributeDetails(
    name = "portrait_capture_date",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Capture Date of Portrait Image"),
)
val SexAttribute = AttributeDetails(
    name = "sex",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Sex"),
)
val HeightAttribute = AttributeDetails(
    name = "height",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Height"),
)
val WeightAttribute = AttributeDetails(
    name = "weight",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Weight"),
)
val HairColourAttribute = AttributeDetails(
    name = "hair_colour",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Hair Colour"),
)
val BirthPlaceAttribute = AttributeDetails(
    name = "birth_place",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Birth Place"),
)
val ResidentAddressAttribute = AttributeDetails(
    name = "resident_address",
    mandatory = false,
    display = buildMap {
        put(Locale.ENGLISH, "Resident Address")
    },
)
val EyeColourAttribute = AttributeDetails(
    name = "eye_colour",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Eye Colour"),
)
val ResidentCityAttribute = AttributeDetails(
    name = "resident_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Resident City"),
)
val ResidentStateAttribute = AttributeDetails(
    name = "resident_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Resident State"),
)
val ResidentPostalCodeAttribute = AttributeDetails(
    name = "resident_postal_code",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Resident Postal Code"),
)
val ResidentCountryAttribute = AttributeDetails(
    name = "resident_country",
    mandatory = false,
    display = buildMap {
        put(Locale.ENGLISH, "Resident Country")
    },
)
val AgeInYearsAttribute = AttributeDetails(
    name = "age_in_years",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Age in Years"),
)
val AgeBirthYearAttribute = AttributeDetails(
    name = "age_birth_year",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Age Year of Birth"),
)
val AgeOver18Attribute = AttributeDetails(
    name = "age_over_18",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Age Over 18"),
)
val AgeOver21Attribute = AttributeDetails(
    name = "age_over_21",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Age Over 21"),
)
val NationalityAttribute = AttributeDetails(
    name = "nationality",
    mandatory = false,
    display = buildMap {
        put(Locale.ENGLISH, "Nationality")
    },
)
val FamilyNameNationalCharacterAttribute = AttributeDetails(
    name = "family_name_national_character",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "National Family Name(s)"),
)
val GivenNameNationalCharacterAttribute = AttributeDetails(
    name = "given_name_national_character",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "National Given Name(s)"),
)
val SignatureUsualMarkAttribute = AttributeDetails(
    name = "signature_usual_mark",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Signature"),
)
val IssuingCountryAttribute = AttributeDetails(
    name = "issuing_country",
    mandatory = true,
    display = buildMap {
        put(Locale.ENGLISH, "Issuing Country")
    },
)
val IssuingAuthorityAttribute = AttributeDetails(
    name = "issuing_authority",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Issuing Authority"),
)
val IssuingCountryDistinguishingSignAttribute = AttributeDetails(
    name = "un_distinguishing_sign",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Distinguishing Sign"),
)
val IssuingJurisdictionAttribute = AttributeDetails(
    name = "issuing_jurisdiction",
    mandatory = false,
    display = buildMap {
        put(Locale.ENGLISH, "Issuing Jurisdiction")
    },
)
val DocumentNumberAttribute = AttributeDetails(
    name = "document_number",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Document Number"),
)
val AdministrativeNumberAttribute = AttributeDetails(
    name = "administrative_number",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Administrative Number"),
)
val DrivingPrivilegesAttribute = AttributeDetails(
    name = "driving_privileges",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Driving Privileges"),
)
val MobileDrivingLicenceV1Attributes: List<AttributeDetails> = listOf(
    FamilyNameAttribute,
    GivenNameAttribute,
    BirthDateAttribute,
    IssueDateAttribute,
    ExpiryDateAttribute,
    IssuingCountryAttribute,
    IssuingAuthorityAttribute,
    DocumentNumberAttribute,
    PortraitAttribute,
    DrivingPrivilegesAttribute,
    IssuingCountryDistinguishingSignAttribute,
    AdministrativeNumberAttribute,
    SexAttribute,
    HeightAttribute,
    WeightAttribute,
    EyeColourAttribute,
    HairColourAttribute,
    BirthPlaceAttribute,
    ResidentAddressAttribute,
    PortraitCaptureDateAttribute,
    AgeInYearsAttribute,
    AgeBirthYearAttribute,
    AgeOver18Attribute,
    AgeOver21Attribute,
    IssuingJurisdictionAttribute,
    NationalityAttribute,
    ResidentCityAttribute,
    ResidentStateAttribute,
    ResidentPostalCodeAttribute,
    ResidentCountryAttribute,
    FamilyNameNationalCharacterAttribute,
    GivenNameNationalCharacterAttribute,
    SignatureUsualMarkAttribute,
)

val MobileDrivingLicenceDisplay: List<CredentialDisplay> = listOf(
    CredentialDisplay(
        name = DisplayName("Mobile Driving Licence", Locale.ENGLISH),
    ),
)

val MobileDrivingLicenceV1: MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(MobileDrivingLicenceV1Scope.value),
        docType = mdlDocType(1u),
        display = MobileDrivingLicenceDisplay,
        msoClaims = mapOf(MobileDrivingLicenceV1Namespace to MobileDrivingLicenceV1Attributes),
        cryptographicBindingMethodsSupported = emptySet(),
        credentialSigningAlgorithmsSupported = emptySet(),
        scope = MobileDrivingLicenceV1Scope,
        proofTypesSupported = ProofTypesSupported(
            nonEmptySetOf(
                ProofType.Jwt(
                    signingAlgorithmsSupported = nonEmptySetOf(JWSAlgorithm.ES256),
                    keyAttestation = KeyAttestation.NotRequired,
                ),
            ),
        ),
        policy = MsoMdocPolicy(oneTimeUse = false),
    )

/**
 * Issuing service for Mobile Driving Licence.
 */
internal class IssueMobileDrivingLicence(
    private val validateProofs: ValidateProofs,
    private val getMobileDrivingLicenceData: GetMobileDrivingLicenceData,
    private val encodeMobileDrivingLicenceInCbor: EncodeMobileDrivingLicenceInCbor,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val clock: Clock,
    private val storeIssuedCredentials: StoreIssuedCredentials,
) : IssueSpecificCredential {

    override val supportedCredential: MsoMdocCredentialConfiguration
        get() = MobileDrivingLicenceV1

    override val publicKey: JWK?
        get() = null

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Issuing mDL")
        val holderKeys = with(jwkExtensions()) {
            validateProofs(request.unvalidatedProofs, supportedCredential, clock.instant()).bind()
                .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
        }
        val licence = getMobileDrivingLicenceData(authorizationContext).bind()
        ensureNotNull(licence) {
            IssueCredentialError.Unexpected("Unable to fetch mDL data")
        }

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null

        val issuedCredentials = holderKeys.map { holderKey ->
            val cbor = encodeMobileDrivingLicenceInCbor(licence, holderKey).bind()
            cbor to holderKey.toPublicJWK()
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) {
            IssueCredentialError.Unexpected("Unable to issue mDL")
        }

        storeIssuedCredentials(
            IssuedCredentials(
                format = MSO_MDOC_FORMAT,
                type = supportedCredential.docType,
                holder = with(licence.driver) {
                    "${familyName.latin.value} ${givenName.latin.value}"
                },
                holderPublicKeys = issuedCredentials.map { it.second },
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(issuedCredentials.map { JsonPrimitive(it.first) }, notificationId)
            .also {
                log.info("Successfully issued mDL(s)")
                log.debug("Issued mDL(s) data {}", it)
            }
    }

    companion object {
        private val log = LoggerFactory.getLogger(IssueMobileDrivingLicence::class.java)
    }
}
