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
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.MsoMdocSigner
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import kotlin.time.Duration

class DefaultEncodeMobileDrivingLicenceInCbor(
    clock: Clock,
    issuerSigningKey: IssuerSigningKey,
    validityDuration: Duration,
) : EncodeMobileDrivingLicenceInCbor {

    private val signer = MsoMdocSigner<MobileDrivingLicence>(
        clock = clock,
        issuerSigningKey = issuerSigningKey,
        validityDuration = validityDuration,
        docType = MobileDrivingLicenceV1.docType,
    ) { licence ->
        addItemsToSign(licence)
    }

    override suspend fun invoke(licence: MobileDrivingLicence, holderKey: ECKey): Either<Unexpected, String> =
        Either.catch { signer.sign(licence, holderKey) }.mapLeft { Unexpected("Failed to encode mDL", it) }
}

private fun MDocBuilder.addItemsToSign(licence: MobileDrivingLicence) {
    addItemsToSign(licence.driver)
    addItemsToSign(licence.issueAndExpiry)
    addItemsToSign(licence.issuer)
    addItemToSign(MsoMdocMdlV1Attributes.DocumentNumber, licence.documentNumber.value.toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.DrivingPrivileges, licence.privileges.map { it.toDE() }.toDataElement())
    licence.administrativeNumber?.let { addItemToSign(MsoMdocMdlV1Attributes.AdministrativeNumber, it.value.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(driver: Driver) {
    addItemToSign(MsoMdocMdlV1Attributes.FamilyName, driver.familyName.latin.value.toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.GivenName, driver.givenName.latin.value.toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.BirthDate, driver.birthDate.toKotlinLocalDate().toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.Portrait, driver.portrait.image.content.toDataElement())
    driver.portrait.capturedAt?.let {
        addItemToSign(
            MsoMdocMdlV1Attributes.PortraitCaptureDate,
            it.toLocalDate().toKotlinLocalDate().toDataElement(),
        )
    }
    driver.sex?.let { addItemToSign(MsoMdocMdlV1Attributes.Sex, it.code.toDataElement()) }
    driver.height?.let { addItemToSign(MsoMdocMdlV1Attributes.Height, it.value.toDataElement()) }
    driver.weight?.let { addItemToSign(MsoMdocMdlV1Attributes.Weight, it.value.toDataElement()) }
    driver.eyeColour?.let { addItemToSign(MsoMdocMdlV1Attributes.EyeColour, it.code.toDataElement()) }
    driver.hairColour?.let { addItemToSign(MsoMdocMdlV1Attributes.HairColour, it.code.toDataElement()) }
    driver.birthPlace?.let { addItemToSign(MsoMdocMdlV1Attributes.BirthPlace, it.value.toDataElement()) }
    driver.residence?.let { residence ->
        residence.address?.let { addItemToSign(MsoMdocMdlV1Attributes.ResidentAddress, it.value.toDataElement()) }
        residence.city?.let { addItemToSign(MsoMdocMdlV1Attributes.ResidentCity, it.value.toDataElement()) }
        residence.state?.let { addItemToSign(MsoMdocMdlV1Attributes.ResidentState, it.value.toDataElement()) }
        residence.postalCode?.let { addItemToSign(MsoMdocMdlV1Attributes.ResidentPostalCode, it.value.toDataElement()) }
        addItemToSign(MsoMdocMdlV1Attributes.ResidentCountry, residence.country.code.toDataElement())
    }
    driver.age?.let { age ->
        addItemToSign(MsoMdocMdlV1Attributes.AgeInYears, age.value.value.toDataElement())
        age.birthYear?.let { addItemToSign(MsoMdocMdlV1Attributes.AgeBirthYear, it.value.toDataElement()) }
        addItemToSign(MsoMdocMdlV1Attributes.AgeOver18, age.over18.toDataElement())
        addItemToSign(MsoMdocMdlV1Attributes.AgeOver21, age.over21.toDataElement())
    }
    driver.nationality?.let { addItemToSign(MsoMdocMdlV1Attributes.Nationality, it.code.toDataElement()) }
    driver.familyName.utf8?.let { addItemToSign(MsoMdocMdlV1Attributes.FamilyNameNationalCharacter, it.toDataElement()) }
    driver.givenName.utf8?.let { addItemToSign(MsoMdocMdlV1Attributes.GivenNameNationalCharacter, it.toDataElement()) }
    driver.signature?.let { addItemToSign(MsoMdocMdlV1Attributes.SignatureUsualMark, it.content.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(MsoMdocMdlV1Attributes.IssueDate, issueAndExpiry.issuedAt.toKotlinLocalDate().toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.ExpiryDate, issueAndExpiry.expiresAt.toKotlinLocalDate().toDataElement())
}

private fun MDocBuilder.addItemsToSign(issuer: Issuer) {
    addItemToSign(MsoMdocMdlV1Attributes.IssuingCountry, issuer.country.countryCode.code.toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.IssuingAuthority, issuer.authority.value.toDataElement())
    addItemToSign(MsoMdocMdlV1Attributes.IssuingCountryDistinguishingSign, issuer.country.distinguishingSign.code.toDataElement())
    issuer.jurisdiction?.let { addItemToSign(MsoMdocMdlV1Attributes.IssuingJurisdiction, it.value.toDataElement()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement) {
    addItemToSign(MobileDrivingLicenceV1Namespace, attr.name, value)
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
                is GenericRestriction -> Triple(code, null, null)
                is ParameterizedRestriction.VehiclePower -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )

                is ParameterizedRestriction.VehicleAuthorizedMass -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )

                is ParameterizedRestriction.VehicleCylinderCapacity -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )

                is ParameterizedRestriction.VehicleAuthorizedPassengerSeats -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )
            }

        put("code", code.toDataElement())
        sign?.let { put("sign", it.toDataElement()) }
        value?.let { put("value", it.toDataElement()) }
    }.toDataElement()
