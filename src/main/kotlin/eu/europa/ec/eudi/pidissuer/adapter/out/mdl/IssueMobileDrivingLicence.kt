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
import arrow.core.NonEmptySet
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
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
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.time.Duration

val MobileDrivingLicenceV1Scope: Scope = Scope(mdlDocType(1u))

val MobileDrivingLicenceV1Namespace: MsoNameSpace = mdlNamespace(1u)

internal object MsoMdocMdlV1Claims {

    val FamilyName = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "family_name",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Family Name(s)"),
    )
    val GivenName = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "given_name",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Given Name(s)"),
    )
    val BirthDate = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "birth_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Birth Date"),
    )
    val IssueDate = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "issue_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuance Date"),
    )
    val ExpiryDate = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "expiry_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Expiry Date"),
    )
    val Portrait = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "portrait",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Portrait Image"),
    )
    val PortraitCaptureDate = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "portrait_capture_date",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Capture Date of Portrait Image"),
    )
    val Sex = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "sex",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Sex"),
    )
    val Height = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "height",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Height"),
    )
    val Weight = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "weight",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Weight"),
    )
    val HairColour = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "hair_colour",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Hair Colour"),
    )
    val BirthPlace = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "birth_place",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Birth Place"),
    )
    val ResidentAddress = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "resident_address",
        mandatory = false,
        display = buildMap {
            put(Locale.ENGLISH, "Resident Address")
        },
    )
    val EyeColour = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "eye_colour",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Eye Colour"),
    )
    val ResidentCity = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "resident_city",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident City"),
    )
    val ResidentState = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "resident_state",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident State"),
    )
    val ResidentPostalCode = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "resident_postal_code",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident Postal Code"),
    )
    val ResidentCountry = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "resident_country",
        mandatory = false,
        display = buildMap {
            put(Locale.ENGLISH, "Resident Country")
        },
    )
    val AgeInYears = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "age_in_years",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age in Years"),
    )
    val AgeBirthYear = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "age_birth_year",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Year of Birth"),
    )
    val AgeOver18 = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "age_over_18",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Over 18"),
    )
    val AgeOver21 = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "age_over_21",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Over 21"),
    )
    val Nationality = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "nationality",
        mandatory = false,
        display = buildMap {
            put(Locale.ENGLISH, "Nationality")
        },
    )
    val FamilyNameNationalCharacter = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "family_name_national_character",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "National Family Name(s)"),
    )
    val GivenNameNationalCharacter = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "given_name_national_character",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "National Given Name(s)"),
    )
    val SignatureUsualMark = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "signature_usual_mark",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Signature"),
    )
    val IssuingCountry = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "issuing_country",
        mandatory = true,
        display = buildMap {
            put(Locale.ENGLISH, "Issuing Country")
        },
    )
    val IssuingAuthority = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "issuing_authority",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuing Authority"),
    )
    val IssuingCountryDistinguishingSign = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "un_distinguishing_sign",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Distinguishing Sign"),
    )
    val IssuingJurisdiction = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "issuing_jurisdiction",
        mandatory = false,
        display = buildMap {
            put(Locale.ENGLISH, "Issuing Jurisdiction")
        },
    )
    val DocumentNumber = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "document_number",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Document Number"),
    )
    val AdministrativeNumber = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "administrative_number",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Administrative Number"),
    )
    val DrivingPrivileges = ClaimDefinition(
        MobileDrivingLicenceV1Namespace,
        "driving_privileges",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Driving Privileges"),
    )

    fun all(): List<ClaimDefinition> = listOf(
        FamilyName,
        GivenName,
        BirthDate,
        IssueDate,
        ExpiryDate,
        IssuingCountry,
        IssuingAuthority,
        DocumentNumber,
        Portrait,
        DrivingPrivileges,
        IssuingCountryDistinguishingSign,
        AdministrativeNumber,
        Sex,
        Height,
        Weight,
        EyeColour,
        HairColour,
        BirthPlace,
        ResidentAddress,
        PortraitCaptureDate,
        AgeInYears,
        AgeBirthYear,
        AgeOver18,
        AgeOver21,
        IssuingJurisdiction,
        Nationality,
        ResidentCity,
        ResidentState,
        ResidentPostalCode,
        ResidentCountry,
        FamilyNameNationalCharacter,
        GivenNameNationalCharacter,
        SignatureUsualMark,
    )
}

val MobileDrivingLicenceV1CredentialConfigurationId: CredentialConfigurationId =
    CredentialConfigurationId(MobileDrivingLicenceV1Scope.value)

val MobileDrivingLicenceV1DocType: MsoDocType = mdlDocType(1u)

internal fun mobileDrivingLicenceV1(
    proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    keyAttestationRequirement: KeyAttestationRequirement,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = MobileDrivingLicenceV1CredentialConfigurationId,
        docType = MobileDrivingLicenceV1DocType,
        display = listOf(
            CredentialDisplay(
                name = DisplayName("Mobile Driving Licence (MSO MDoc)", Locale.ENGLISH),
            ),
        ),
        claims = MsoMdocMdlV1Claims.all(),
        cryptographicBindingMethodsSupported = setOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = null,
        scope = MobileDrivingLicenceV1Scope,
        proofTypesSupported = ProofTypesSupported(
            ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement),
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
    private val validityDuration: Duration,
    private val storeIssuedCredentials: StoreIssuedCredentials,
    jwtProofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    override val keyAttestationRequirement: KeyAttestationRequirement = KeyAttestationRequirement.NotRequired,
) : IssueSpecificCredential {

    override val supportedCredential: MsoMdocCredentialConfiguration =
        mobileDrivingLicenceV1(jwtProofsSupportedSigningAlgorithms, keyAttestationRequirement)

    override val publicKey: JWK?
        get() = null

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Issuing mDL")
        val holderKeys = with(jwkExtensions()) {
            validateProofs(request.unvalidatedProofs, supportedCredential, clock.now()).bind()
                .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
        }
        val licence = getMobileDrivingLicenceData(authorizationContext).bind()
        ensureNotNull(licence) {
            IssueCredentialError.Unexpected("Unable to fetch mDL data")
        }

        val issuedAt = clock.now()
        val expiresAt = issuedAt + validityDuration

        val issuedCredentials = holderKeys.parMap(Dispatchers.Default, 4) { holderKey ->
            encodeMobileDrivingLicenceInCbor(licence, holderKey, issuedAt = issuedAt, expiresAt = expiresAt).bind()
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) {
            IssueCredentialError.Unexpected("Unable to issue mDL")
        }

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null

        storeIssuedCredentials(
            IssuedCredentials(
                format = MSO_MDOC_FORMAT,
                type = supportedCredential.docType,
                holder = with(licence.driver) {
                    "${familyName.latin.value} ${givenName.latin.value}"
                },
                holderPublicKeys = holderKeys,
                issuedAt = issuedAt,
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(issuedCredentials.map { JsonPrimitive(it) }, notificationId)
            .also {
                log.info("Successfully issued mDL(s)")
                log.debug("Issued mDL(s) data {}", it)
            }
    }

    companion object {
        private val log = LoggerFactory.getLogger(IssueMobileDrivingLicence::class.java)
    }
}
