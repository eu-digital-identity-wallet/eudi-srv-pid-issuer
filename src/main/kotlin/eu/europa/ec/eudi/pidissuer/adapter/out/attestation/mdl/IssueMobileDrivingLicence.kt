/*
 * Copyright (c) 2023-2026 European Commission
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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl

import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.coseAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.EncodeAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.toTDate
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import kotlinx.datetime.toKotlinLocalDate
import java.time.ZoneOffset
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.toKotlinInstant

val MobileDrivingLicenceV1Scope: Scope = Scope(mdlDocType(1u))

val MobileDrivingLicenceV1Namespace: MsoNameSpace = mdlNamespace(1u)

internal object MsoMdocMdlV1Claims {
    val FamilyName =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "family_name",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Family Name(s)"),
        )
    val GivenName =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "given_name",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Given Name(s)"),
        )
    val BirthDate =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "birth_date",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Birth Date"),
        )
    val IssueDate =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "issue_date",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuance Date"),
        )
    val ExpiryDate =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "expiry_date",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Expiry Date"),
        )
    val Portrait =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "portrait",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Portrait Image"),
        )
    val PortraitCaptureDate =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "portrait_capture_date",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Capture Date of Portrait Image"),
        )
    val Sex =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "sex",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Sex"),
        )
    val Height =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "height",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Height"),
        )
    val Weight =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "weight",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Weight"),
        )
    val HairColour =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "hair_colour",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Hair Colour"),
        )
    val BirthPlace =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "birth_place",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Birth Place"),
        )
    val ResidentAddress =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "resident_address",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Resident Address")
                },
        )
    val EyeColour =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "eye_colour",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Eye Colour"),
        )
    val ResidentCity =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "resident_city",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident City"),
        )
    val ResidentState =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "resident_state",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident State"),
        )
    val ResidentPostalCode =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "resident_postal_code",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident Postal Code"),
        )
    val ResidentCountry =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "resident_country",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Resident Country")
                },
        )
    val AgeInYears =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "age_in_years",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age in Years"),
        )
    val AgeBirthYear =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "age_birth_year",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Year of Birth"),
        )
    val AgeOver18 =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "age_over_18",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Over 18"),
        )
    val AgeOver21 =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "age_over_21",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Over 21"),
        )
    val Nationality =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "nationality",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Nationality")
                },
        )
    val FamilyNameNationalCharacter =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "family_name_national_character",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "National Family Name(s)"),
        )
    val GivenNameNationalCharacter =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "given_name_national_character",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "National Given Name(s)"),
        )
    val SignatureUsualMark =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "signature_usual_mark",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Signature"),
        )
    val IssuingCountry =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "issuing_country",
            mandatory = true,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Issuing Country")
                },
        )
    val IssuingAuthority =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "issuing_authority",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority"),
        )
    val IssuingCountryDistinguishingSign =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "un_distinguishing_sign",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Distinguishing Sign"),
        )
    val IssuingJurisdiction =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "issuing_jurisdiction",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Issuing Jurisdiction")
                },
        )
    val DocumentNumber =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "document_number",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Document Number"),
        )
    val AdministrativeNumber =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "administrative_number",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Administrative Number"),
        )
    val DrivingPrivileges =
        ClaimDefinition(
            MobileDrivingLicenceV1Namespace,
            "driving_privileges",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Driving Privileges"),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
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
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = MobileDrivingLicenceV1CredentialConfigurationId,
        docType = MobileDrivingLicenceV1DocType,
        display =
            listOf(
                CredentialDisplay(
                    name = DisplayName("Mobile Driving Licence (MSO MDoc)", Locale.ENGLISH),
                ),
            ),
        claims = MsoMdocMdlV1Claims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = MobileDrivingLicenceV1Scope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Eaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

@Deprecated("Use the other constructor instead")
@Suppress("FunctionName")
fun IssueMobileDrivingLicence(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<MobileDrivingLicence>,
    allocateStatus: AllocateStatus,
    encodeAttributes: EncodeAttributesInMdoc<MobileDrivingLicence>,
): IssueMdoc<MobileDrivingLicence> {
    val configuration =
        mobileDrivingLicenceV1(encodeAttributes.signingAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        encodeAttributes,
    )
}

@Suppress("FunctionName")
fun IssueMobileDrivingLicence(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<MobileDrivingLicence>,
    allocateStatus: AllocateStatus,
    issuerSigningKey: IssuerSigningKey,
): IssueMdoc<MobileDrivingLicence> {
    val configuration =
        mobileDrivingLicenceV1(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    val encodeAttributes = encodeMdlInMdoc(configuration.docType, issuerSigningKey)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        encodeAttributes,
    )
}

private fun encodeMdlInMdoc(
    docType: MsoDocType = MobileDrivingLicenceV1DocType,
    issuerSigningKey: IssuerSigningKey,
): EncodeAttributesInMdoc<MobileDrivingLicence> =
    EncodeAttributesInMdoc(docType, issuerSigningKey) { licence ->
        addItemsToSign(licence)
    }

private fun MDocBuilder.addItemsToSign(licence: MobileDrivingLicence) {
    addItemsToSign(licence.driver)
    addItemsToSign(licence.issueAndExpiry)
    addItemsToSign(licence.issuer)
    addItemToSign(MsoMdocMdlV1Claims.DocumentNumber, licence.documentNumber.value.toDataElement())
    addItemToSign(MsoMdocMdlV1Claims.DrivingPrivileges, licence.privileges.map { it.toDE() }.toDataElement())
    licence.administrativeNumber?.let {
        addItemToSign(
            MsoMdocMdlV1Claims.AdministrativeNumber,
            it.value.toDataElement(),
        )
    }
}

private fun MDocBuilder.addItemsToSign(driver: Driver) {
    addItemToSign(
        MsoMdocMdlV1Claims.FamilyName,
        driver.familyName.latin.value
            .toDataElement(),
    )
    addItemToSign(
        MsoMdocMdlV1Claims.GivenName,
        driver.givenName.latin.value
            .toDataElement(),
    )
    addItemToSign(MsoMdocMdlV1Claims.BirthDate, driver.birthDate.toKotlinLocalDate().toDataElement())
    addItemToSign(
        MsoMdocMdlV1Claims.Portrait,
        driver.portrait.image.content
            .toDataElement(),
    )
    driver.portrait.capturedAt?.let {
        addItemToSign(
            MsoMdocMdlV1Claims.PortraitCaptureDate,
            it.toInstant(ZoneOffset.UTC).toKotlinInstant().toTDate(),
        )
    }
    driver.sex?.let { addItemToSign(MsoMdocMdlV1Claims.Sex, it.code.toDataElement()) }
    driver.height?.let { addItemToSign(MsoMdocMdlV1Claims.Height, it.value.toDataElement()) }
    driver.weight?.let { addItemToSign(MsoMdocMdlV1Claims.Weight, it.value.toDataElement()) }
    driver.eyeColour?.let { addItemToSign(MsoMdocMdlV1Claims.EyeColour, it.code.toDataElement()) }
    driver.hairColour?.let { addItemToSign(MsoMdocMdlV1Claims.HairColour, it.code.toDataElement()) }
    driver.birthPlace?.let { addItemToSign(MsoMdocMdlV1Claims.BirthPlace, it.value.toDataElement()) }
    driver.residence?.let { residence ->
        residence.address?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentAddress, it.value.toDataElement()) }
        residence.city?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentCity, it.value.toDataElement()) }
        residence.state?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentState, it.value.toDataElement()) }
        residence.postalCode?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentPostalCode, it.value.toDataElement()) }
        addItemToSign(MsoMdocMdlV1Claims.ResidentCountry, residence.country.code.toDataElement())
    }
    driver.age?.let { age ->
        addItemToSign(MsoMdocMdlV1Claims.AgeInYears, age.value.value.toDataElement())
        age.birthYear?.let { addItemToSign(MsoMdocMdlV1Claims.AgeBirthYear, it.value.toDataElement()) }
        addItemToSign(MsoMdocMdlV1Claims.AgeOver18, age.over18.toDataElement())
        addItemToSign(MsoMdocMdlV1Claims.AgeOver21, age.over21.toDataElement())
    }
    driver.nationality?.let { addItemToSign(MsoMdocMdlV1Claims.Nationality, it.code.toDataElement()) }
    driver.familyName.utf8?.let { addItemToSign(MsoMdocMdlV1Claims.FamilyNameNationalCharacter, it.toDataElement()) }
    driver.givenName.utf8?.let { addItemToSign(MsoMdocMdlV1Claims.GivenNameNationalCharacter, it.toDataElement()) }
    driver.signature?.let { addItemToSign(MsoMdocMdlV1Claims.SignatureUsualMark, it.content.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(MsoMdocMdlV1Claims.IssueDate, issueAndExpiry.issuedAt.toKotlinLocalDate().toDataElement())
    addItemToSign(MsoMdocMdlV1Claims.ExpiryDate, issueAndExpiry.expiresAt.toKotlinLocalDate().toDataElement())
}

private fun MDocBuilder.addItemsToSign(issuer: Issuer) {
    addItemToSign(
        MsoMdocMdlV1Claims.IssuingCountry,
        issuer.country.countryCode.code
            .toDataElement(),
    )
    addItemToSign(MsoMdocMdlV1Claims.IssuingAuthority, issuer.authority.value.toDataElement())
    addItemToSign(
        MsoMdocMdlV1Claims.IssuingCountryDistinguishingSign,
        issuer.country.distinguishingSign.code
            .toDataElement(),
    )
    issuer.jurisdiction?.let { addItemToSign(MsoMdocMdlV1Claims.IssuingJurisdiction, it.value.toDataElement()) }
}

private fun MDocBuilder.addItemToSign(
    claim: ClaimDefinition,
    value: DataElement,
) {
    addItemToSign(MobileDrivingLicenceV1Namespace, claim.name, value)
}

private fun DrivingPrivilege.toDE() =
    buildMap {
        put("vehicle_category_code", vehicleCategory.code.toDataElement())
        issueAndExpiry?.let { issueAndExpiry ->
            put("issue_date", issueAndExpiry.issuedAt.toKotlinLocalDate().toDataElement())
            put("expiry_date", issueAndExpiry.expiresAt.toKotlinLocalDate().toDataElement())
        }
        restrictions?.let { restrictions ->
            put("codes", restrictions.map { it.toDE() }.toDataElement())
        }
    }.toDataElement()

private fun DrivingPrivilege.Restriction.toDE() =
    buildMap {
        val (code, sign, value) =
            when (this@toDE) {
                is GenericRestriction -> {
                    Triple(code, null, null)
                }

                is ParameterizedRestriction.VehiclePower -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }

                is ParameterizedRestriction.VehicleAuthorizedMass -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }

                is ParameterizedRestriction.VehicleCylinderCapacity -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }

                is ParameterizedRestriction.VehicleAuthorizedPassengerSeats -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }
            }

        put("code", code.toDataElement())
        sign?.let { put("sign", it.toDataElement()) }
        value?.let { put("value", it.toString().toDataElement()) }
    }.toDataElement()
