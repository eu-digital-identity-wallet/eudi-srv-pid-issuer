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

import arrow.core.nel
import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.coseAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.encodeAttestationAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.toTDate
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
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.toKotlinInstant

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
        mdlV1Cfg(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        encodeAttestationAttributesInMdoc(configuration.docType, issuerSigningKey) { licence ->
            addItemsToSign(licence)
        },
    )
}

internal fun mdlV1Cfg(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration {
    val scope = Scope(mdlDocType(1u))
    return MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(scope.value),
        docType = mdlDocType(1u),
        display = CredentialDisplay(DisplayName.en("Mobile Driving Licence (MSO MDoc)")).nel(),
        claims = MsoMdocMdlV1Claims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = scope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Eaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )
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
    addItemToSign(MsoMdocMdlV1Claims.nameSpace, claim.name, value)
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
