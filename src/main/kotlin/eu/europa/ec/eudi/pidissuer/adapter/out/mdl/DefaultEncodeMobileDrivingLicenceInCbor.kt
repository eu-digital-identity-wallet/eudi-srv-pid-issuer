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

import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.MsoMdocSigner
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
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
    docType: MsoDocType,
) : EncodeMobileDrivingLicenceInCbor {

    private val signer = MsoMdocSigner<MobileDrivingLicence>(
        clock = clock,
        issuerSigningKey = issuerSigningKey,
        validityDuration = validityDuration,
        docType = docType,
    ) { licence ->
        addItemsToSign(licence)
    }

    context(Raise<Unexpected>)
    override suspend fun invoke(licence: MobileDrivingLicence, holderKey: ECKey): String =
        try {
            signer.sign(licence, holderKey)
        } catch (t: Throwable) {
            raise(Unexpected("Failed to encode mDL", t))
        }
}

private fun MDocBuilder.addItemsToSign(licence: MobileDrivingLicence) {
    addItemsToSign(licence.driver)
    addItemsToSign(licence.issueAndExpiry)
    addItemsToSign(licence.issuer)
    addItemToSign(DocumentNumberAttribute, licence.documentNumber.value.toDataElement())
    addItemToSign(DrivingPrivilegesAttribute, licence.privileges.map { it.toDE() }.toDataElement())
    licence.administrativeNumber?.let { addItemToSign(AdministrativeNumberAttribute, it.value.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(driver: Driver) {
    addItemToSign(FamilyNameAttribute, driver.familyName.latin.value.toDataElement())
    addItemToSign(GivenNameAttribute, driver.givenName.latin.value.toDataElement())
    addItemToSign(BirthDateAttribute, driver.birthDate.toKotlinLocalDate().toDataElement())
    addItemToSign(PortraitAttribute, driver.portrait.image.content.toDataElement())
    driver.portrait.capturedAt?.let {
        addItemToSign(
            PortraitCaptureDateAttribute,
            it.toLocalDate().toKotlinLocalDate().toDataElement(),
        )
    }
    driver.sex?.let { addItemToSign(SexAttribute, it.code.toDataElement()) }
    driver.height?.let { addItemToSign(HeightAttribute, it.value.toDataElement()) }
    driver.weight?.let { addItemToSign(WeightAttribute, it.value.toDataElement()) }
    driver.eyeColour?.let { addItemToSign(EyeColourAttribute, it.code.toDataElement()) }
    driver.hairColour?.let { addItemToSign(HairColourAttribute, it.code.toDataElement()) }
    driver.birthPlace?.let { addItemToSign(BirthPlaceAttribute, it.value.toDataElement()) }
    driver.residence?.let { residence ->
        residence.address?.let { addItemToSign(ResidentAddressAttribute, it.value.toDataElement()) }
        residence.city?.let { addItemToSign(ResidentCityAttribute, it.value.toDataElement()) }
        residence.state?.let { addItemToSign(ResidentStateAttribute, it.value.toDataElement()) }
        residence.postalCode?.let { addItemToSign(ResidentPostalCodeAttribute, it.value.toDataElement()) }
        addItemToSign(ResidentCountryAttribute, residence.country.code.toDataElement())
    }
    driver.age?.let { age ->
        addItemToSign(AgeInYearsAttribute, age.value.value.toDataElement())
        age.birthYear?.let { addItemToSign(AgeBirthYearAttribute, it.value.toDataElement()) }
        addItemToSign(AgeOver18Attribute, age.over18.toDataElement())
        addItemToSign(AgeOver21Attribute, age.over21.toDataElement())
    }
    driver.nationality?.let { addItemToSign(NationalityAttribute, it.code.toDataElement()) }
    driver.familyName.utf8?.let { addItemToSign(FamilyNameNationalCharacterAttribute, it.toDataElement()) }
    driver.givenName.utf8?.let { addItemToSign(GivenNameNationalCharacterAttribute, it.toDataElement()) }
    driver.signature?.let { addItemToSign(SignatureUsualMarkAttribute, it.content.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(IssueDateAttribute, issueAndExpiry.issuedAt.toKotlinLocalDate().toDataElement())
    addItemToSign(ExpiryDateAttribute, issueAndExpiry.expiresAt.toKotlinLocalDate().toDataElement())
}

private fun MDocBuilder.addItemsToSign(issuer: Issuer) {
    addItemToSign(IssuingCountryAttribute, issuer.country.countryCode.code.toDataElement())
    addItemToSign(IssuingAuthorityAttribute, issuer.authority.value.toDataElement())
    addItemToSign(IssuingCountryDistinguishingSignAttribute, issuer.country.distinguishingSign.code.toDataElement())
    issuer.jurisdiction?.let { addItemToSign(IssuingJurisdictionAttribute, it.value.toDataElement()) }
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
