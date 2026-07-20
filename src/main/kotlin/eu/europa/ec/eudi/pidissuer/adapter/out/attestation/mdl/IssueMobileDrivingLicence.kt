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
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.EncodeAttestationAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.addItemToSign
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.toFullDate
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import eu.europa.esig.dss.cbades.cbor.CBORObject
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAClaimParameters
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
        EncodeAttestationAttributesInMdoc(issuerSigningKey, configuration.docType) { addItemsToSign(it) },
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

private fun MdocEAAClaimParameters.addItemsToSign(licence: MobileDrivingLicence) {
    addItemsToSign(licence.driver)
    addItemsToSign(licence.issueAndExpiry)
    addItemsToSign(licence.issuer)
    addItemToSign(MsoMdocMdlV1Claims.DocumentNumber, licence.documentNumber.value)
    addItemToSign(MsoMdocMdlV1Claims.DrivingPrivileges, licence.privileges.map { it.toCBORObject() })
    licence.administrativeNumber?.let { addItemToSign(MsoMdocMdlV1Claims.AdministrativeNumber, it.value) }
}

private fun MdocEAAClaimParameters.addItemsToSign(driver: Driver) {
    addItemToSign(MsoMdocMdlV1Claims.FamilyName, driver.familyName.latin.value)
    addItemToSign(MsoMdocMdlV1Claims.GivenName, driver.givenName.latin.value)
    addItemToSign(MsoMdocMdlV1Claims.BirthDate, driver.birthDate.toKotlinLocalDate())
    addItemToSign(MsoMdocMdlV1Claims.Portrait, driver.portrait.image.content)
    driver.portrait.capturedAt?.let {
        addItemToSign(
            MsoMdocMdlV1Claims.PortraitCaptureDate,
            it.toInstant(ZoneOffset.UTC).toKotlinInstant(),
        )
    }
    driver.sex?.let { addItemToSign(MsoMdocMdlV1Claims.Sex, it.code) }
    driver.height?.let { addItemToSign(MsoMdocMdlV1Claims.Height, it.value) }
    driver.weight?.let { addItemToSign(MsoMdocMdlV1Claims.Weight, it.value) }
    driver.eyeColour?.let { addItemToSign(MsoMdocMdlV1Claims.EyeColour, it.code) }
    driver.hairColour?.let { addItemToSign(MsoMdocMdlV1Claims.HairColour, it.code) }
    driver.birthPlace?.let { addItemToSign(MsoMdocMdlV1Claims.BirthPlace, it.value) }
    driver.residence?.let { residence ->
        residence.address?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentAddress, it.value) }
        residence.city?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentCity, it.value) }
        residence.state?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentState, it.value) }
        residence.postalCode?.let { addItemToSign(MsoMdocMdlV1Claims.ResidentPostalCode, it.value) }
        addItemToSign(MsoMdocMdlV1Claims.ResidentCountry, residence.country.code)
    }
    driver.age?.let { age ->
        addItemToSign(MsoMdocMdlV1Claims.AgeInYears, age.value.value)
        age.birthYear?.let { addItemToSign(MsoMdocMdlV1Claims.AgeBirthYear, it.value) }
        addItemToSign(MsoMdocMdlV1Claims.AgeOver18, age.over18)
        addItemToSign(MsoMdocMdlV1Claims.AgeOver21, age.over21)
    }
    driver.nationality?.let { addItemToSign(MsoMdocMdlV1Claims.Nationality, it.code) }
    driver.familyName.utf8?.let { addItemToSign(MsoMdocMdlV1Claims.FamilyNameNationalCharacter, it) }
    driver.givenName.utf8?.let { addItemToSign(MsoMdocMdlV1Claims.GivenNameNationalCharacter, it) }
    driver.signature?.let { addItemToSign(MsoMdocMdlV1Claims.SignatureUsualMark, it.content) }
}

private fun MdocEAAClaimParameters.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(MsoMdocMdlV1Claims.IssueDate, issueAndExpiry.issuedAt.toKotlinLocalDate())
    addItemToSign(MsoMdocMdlV1Claims.ExpiryDate, issueAndExpiry.expiresAt.toKotlinLocalDate())
}

private fun MdocEAAClaimParameters.addItemsToSign(issuer: Issuer) {
    addItemToSign(MsoMdocMdlV1Claims.IssuingCountry, issuer.country.countryCode.code)
    addItemToSign(MsoMdocMdlV1Claims.IssuingAuthority, issuer.authority.value)
    addItemToSign(MsoMdocMdlV1Claims.IssuingCountryDistinguishingSign, issuer.country.distinguishingSign.code)
    issuer.jurisdiction?.let { addItemToSign(MsoMdocMdlV1Claims.IssuingJurisdiction, it.value) }
}

private fun DrivingPrivilege.toCBORObject(): CBORObject =
    CBORObjectFactory.toCBORObject(
        buildMap {
            put("vehicle_category_code", vehicleCategory.code)
            issueAndExpiry?.let { issueAndExpiry ->
                put("issue_date", issueAndExpiry.issuedAt.toKotlinLocalDate().toFullDate())
                put("expiry_date", issueAndExpiry.expiresAt.toKotlinLocalDate().toFullDate())
            }
            restrictions?.let { restrictions ->
                put("codes", restrictions.map { it.toCBORObject() })
            }
        },
    )

private fun DrivingPrivilege.Restriction.toCBORObject(): CBORObject =
    CBORObjectFactory.toCBORObject(
        buildMap {
            val (code, sign, value) =
                when (this@toCBORObject) {
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

            put("code", code)
            sign?.let { put("sign", it) }
            value?.let { put("value", it.toString()) }
        },
    )
