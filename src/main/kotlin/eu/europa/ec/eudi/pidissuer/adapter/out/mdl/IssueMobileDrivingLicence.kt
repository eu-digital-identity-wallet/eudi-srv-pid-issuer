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

private fun msoMdocMdlV1ClaimPath(name: String): ClaimPath = ClaimPath.msoMDoc(MobileDrivingLicenceV1Namespace, name)

internal object MsoMdocMdlV1Attributes {

    val FamilyName = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("family_name"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Last name, surname, or primary identifier of the mDL holder."),
    )
    val GivenName = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("given_name"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "First name(s), other name(s), or secondary identifier, of the mDL holder."),
    )
    val BirthDate = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("birth_date"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Day, month and year on which the mDL holder was born."),
    )
    val IssueDate = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("issue_date"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Date when mDL was issued."),
    )
    val ExpiryDate = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("expiry_date"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Date when mDL expires."),
    )
    val Portrait = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("portrait"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "A reproduction of the mDL holder’s portrait."),
    )
    val PortraitCaptureDate = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("portrait_capture_date"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Date when portrait was taken."),
    )
    val Sex = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("sex"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "mDL holder’s sex using values as defined in ISO/IEC 5218."),
    )
    val Height = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("height"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "mDL holder’s height in centimetres."),
    )
    val Weight = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("weight"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "mDL holder’s weight in kilograms."),
    )
    val HairColour = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("hair_colour"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "mDL holder’s hair colour."),
    )
    val BirthPlace = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("birth_place"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Country and municipality or state/province where the mDL holder was born."),
    )
    val ResidentAddress = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("resident_address"),
        mandatory = false,
        display = buildMap {
            put(
                Locale.ENGLISH,
                "The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).",
            )
        },
    )
    val EyeColour = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("eye_colour"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "mDL holder’s eye colour."),
    )
    val ResidentCity = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("resident_city"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The city where the mDL holder lives."),
    )
    val ResidentState = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("resident_state"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The state/province/district where the mDL holder lives."),
    )
    val ResidentPostalCode = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("resident_postal_code"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The postal code of the mDL holder."),
    )
    val ResidentCountry = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("resident_country"),
        mandatory = false,
        display = buildMap {
            put(
                Locale.ENGLISH,
                "The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.",
            )
        },
    )
    val AgeInYears = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("age_in_years"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The age of the mDL holder."),
    )
    val AgeBirthYear = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("age_birth_year"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The year when the mDL holder was born."),
    )
    val AgeOver18 = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("age_over_18"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Whether the mDL holder is over 18 years old."),
    )
    val AgeOver21 = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("age_over_21"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Whether the mDL holder is over 21 years old."),
    )
    val Nationality = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("nationality"),
        mandatory = false,
        display = buildMap {
            put(
                Locale.ENGLISH,
                "Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1.",
            )
        },
    )
    val FamilyNameNationalCharacter = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("family_name_national_character"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The family name of the mDL holder using full UTF-8 character set."),
    )
    val GivenNameNationalCharacter = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("given_name_national_character"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The given name of the mDL holder using full UTF-8 character set."),
    )
    val SignatureUsualMark = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("signature_usual_mark"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Image of the signature or usual mark of the mDL holder."),
    )
    val IssuingCountry = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("issuing_country"),
        mandatory = true,
        display = buildMap {
            put(
                Locale.ENGLISH,
                "Alpha-2 country code, as defined in ISO 3166-1 of the issuing authority’s country or territory.",
            )
        },
    )
    val IssuingAuthority = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("issuing_authority"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuing authority name."),
    )
    val IssuingCountryDistinguishingSign = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("un_distinguishing_sign"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F."),
    )
    val IssuingJurisdiction = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("issuing_jurisdiction"),
        mandatory = false,
        display = buildMap {
            put(
                Locale.ENGLISH,
                "Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8.",
            )
        },
    )
    val DocumentNumber = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("document_number"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "The number assigned or calculated by the issuing authority."),
    )
    val AdministrativeNumber = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("administrative_number"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "An audit control number assigned by the issuing authority."),
    )
    val DrivingPrivileges = AttributeDetails(
        path = msoMdocMdlV1ClaimPath("driving_privileges"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Driving privileges of the mDL holder."),
    )
    val mdlAttributes: MsoClaims
        get() = MsoClaims(
            mapOf(
                MobileDrivingLicenceV1Namespace to listOf(
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
                ),
            ),
        )
}

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
        msoClaims = MsoMdocMdlV1Attributes.mdlAttributes,
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
