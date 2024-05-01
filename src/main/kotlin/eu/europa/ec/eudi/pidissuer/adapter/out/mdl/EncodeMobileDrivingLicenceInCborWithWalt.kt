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
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDE
import id.walt.mdoc.doc.MDocBuilder
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import kotlin.time.Duration

class EncodeMobileDrivingLicenceInCborWithWalt(
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
    addItemToSign(DocumentNumberAttribute, licence.documentNumber.value.toDE())
    addItemToSign(DrivingPrivilegesAttribute, licence.privileges.map { it.toDE() }.toDE())
    licence.administrativeNumber?.let { addItemToSign(AdministrativeNumberAttribute, it.value.toDE()) }
}

private fun MDocBuilder.addItemsToSign(driver: Driver) {
    addItemToSign(FamilyNameAttribute, driver.familyName.latin.value.toDE())
    addItemToSign(GivenNameAttribute, driver.givenName.latin.value.toDE())
    addItemToSign(BirthDateAttribute, driver.birthDate.toKotlinLocalDate().toDE())
    addItemToSign(PortraitAttribute, driver.portrait.image.content.toDE())
    driver.portrait.capturedAt?.let {
        addItemToSign(
            PortraitCaptureDateAttribute,
            it.toLocalDate().toKotlinLocalDate().toDE(),
        )
    }
    driver.sex?.let { addItemToSign(SexAttribute, it.code.toDE()) }
    driver.height?.let { addItemToSign(HeightAttribute, it.value.toDE()) }
    driver.weight?.let { addItemToSign(WeightAttribute, it.value.toDE()) }
    driver.eyeColour?.let { addItemToSign(EyeColourAttribute, it.code.toDE()) }
    driver.hairColour?.let { addItemToSign(HairColourAttribute, it.code.toDE()) }
    driver.birthPlace?.let { addItemToSign(BirthPlaceAttribute, it.value.toDE()) }
    driver.residence?.let { residence ->
        residence.address?.let { addItemToSign(ResidentAddressAttribute, it.value.toDE()) }
        residence.city?.let { addItemToSign(ResidentCityAttribute, it.value.toDE()) }
        residence.state?.let { addItemToSign(ResidentStateAttribute, it.value.toDE()) }
        residence.postalCode?.let { addItemToSign(ResidentPostalCodeAttribute, it.value.toDE()) }
        addItemToSign(ResidentCountryAttribute, residence.country.code.toDE())
    }
    driver.age?.let { age ->
        addItemToSign(AgeInYearsAttribute, age.value.value.toDE())
        age.birthYear?.let { addItemToSign(AgeBirthYearAttribute, it.value.toDE()) }
        addItemToSign(AgeOver18Attribute, age.over18.toDE())
        addItemToSign(AgeOver21Attribute, age.over21.toDE())
    }
    driver.nationality?.let { addItemToSign(NationalityAttribute, it.code.toDE()) }
    driver.familyName.utf8?.let { addItemToSign(FamilyNameNationalCharacterAttribute, it.toDE()) }
    driver.givenName.utf8?.let { addItemToSign(GivenNameNationalCharacterAttribute, it.toDE()) }
    driver.signature?.let { addItemToSign(SignatureUsualMarkAttribute, it.content.toDE()) }
}

private fun MDocBuilder.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(IssueDateAttribute, issueAndExpiry.issuedAt.toKotlinLocalDate().toDE())
    addItemToSign(ExpiryDateAttribute, issueAndExpiry.expiresAt.toKotlinLocalDate().toDE())
}

private fun MDocBuilder.addItemsToSign(issuer: Issuer) {
    addItemToSign(IssuingCountryAttribute, issuer.country.countryCode.code.toDE())
    addItemToSign(IssuingAuthorityAttribute, issuer.authority.value.toDE())
    addItemToSign(IssuingCountryDistinguishingSignAttribute, issuer.country.distinguishingSign.code.toDE())
    issuer.jurisdiction?.let { addItemToSign(IssuingJurisdictionAttribute, it.value.toDE()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement<*>) {
    addItemToSign(MobileDrivingLicenceV1Namespace, attr.name, value)
}

private fun DrivingPrivilege.toDE() =
    buildMap {
        put("vehicle_category_code", vehicleCategory.code.toDE())
        issueAndExpiry?.let { issueAndExpiry ->
            put("issue_date", issueAndExpiry.issuedAt.toKotlinLocalDate().toDE())
            put("expiry_date", issueAndExpiry.expiresAt.toKotlinLocalDate().toDE())
        }
        restrictions?.let { restrictions ->
            put("codes", restrictions.map { it.toDE() }.toDE())
        }
    }.toDE()

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

        put("code", code.toDE())
        sign?.let { put("sign", it.toDE()) }
        value?.let { put("value", it.toDE()) }
    }.toDE()
