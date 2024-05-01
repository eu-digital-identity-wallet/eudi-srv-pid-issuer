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

import COSE.OneKey
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.cryptoProvider
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.toDE
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toKotlinInstant
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration

@OptIn(ExperimentalEncodingApi::class)
internal class EncodePidInCborWithWalt(
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val validityDuration: Duration,
) : EncodePidInCbor {

    private val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        issuerSigningKey.cryptoProvider()
    }

    override suspend fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: ECKey,
    ): String {
        val validityInfo = validityInfo(clock, validityDuration)
        val deviceKeyInfo = getDeviceKeyInfo(holderKey)
        val mdoc = MDocBuilder(PidMsoMdocV1.docType).apply {
            addItemsToSign(pid)
            addItemsToSign(pidMetaData)
        }.sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, issuerSigningKey.key.keyID)
        return Base64.UrlSafe.encode(mdoc.toCBOR())
    }
}

private fun validityInfo(clock: Clock, duration: Duration): ValidityInfo {
    val signedAt = clock.instant().toKotlinInstant()
    val validTo = signedAt.plus(duration)
    return ValidityInfo(signed = signedAt, validFrom = signedAt, validUntil = validTo, expectedUpdate = null)
}

private fun getDeviceKeyInfo(deviceKey: ECKey): DeviceKeyInfo {
    val key = OneKey(deviceKey.toECPublicKey(), null)
    val deviceKeyDataElement: MapElement = DataElement.fromCBOR(key.AsCBOR().EncodeToBytes())
    return DeviceKeyInfo(deviceKeyDataElement, null, null)
}

private fun MDocBuilder.addItemsToSign(pid: Pid) {
    addItemToSign(GivenNameAttribute, pid.givenName.value.toDE())
    addItemToSign(FamilyNameAttribute, pid.familyName.value.toDE())
    addItemToSign(BirthDateAttribute, pid.birthDate.toKotlinLocalDate().toDE())
    pid.familyNameBirth?.let { addItemToSign(FamilyNameBirthAttribute, it.value.toDE()) }
    pid.givenNameBirth?.let { addItemToSign(GivenNameBirthAttribute, it.value.toDE()) }
    pid.gender?.let { addItemToSign(GenderAttribute, it.value.toDE()) }
    pid.nationality?.let { addItemToSign(NationalityAttribute, it.value.toDE()) }
    pid.ageOver18?.let { addItemToSign(AgeOver18Attribute, it.toDE()) }
    pid.ageBirthYear?.let { addItemToSign(AgeBirthYearAttribute, it.value.toDE()) }
    pid.ageInYears?.let { addItemToSign(AgeInYearsAttribute, it.toDE()) }
    pid.birthPlace?.let { addItemToSign(BirthPlaceAttribute, it.toDE()) }
    pid.birthCountry?.let { addItemToSign(BirthCountryAttribute, it.value.toDE()) }
    pid.birthState?.let { addItemToSign(BirthStateAttribute, it.value.toDE()) }
    pid.birthCity?.let { addItemToSign(BirthCityAttribute, it.value.toDE()) }
    pid.residentAddress?.let { addItemToSign(ResidenceAddress, it.toDE()) }
    pid.residentCountry?.let { addItemToSign(ResidenceCountryAttribute, it.value.toDE()) }
    pid.residentState?.let { addItemToSign(ResidenceStateAttribute, it.value.toDE()) }
    pid.residentCity?.let { addItemToSign(ResidenceCityAttribute, it.value.toDE()) }
    pid.residentPostalCode?.let { addItemToSign(ResidencePostalCodeAttribute, it.value.toDE()) }
    pid.residentStreet?.let { addItemToSign(ResidenceStreetAttribute, it.value.toDE()) }
    pid.residentHouseNumber?.let { addItemToSign(ResidenceHouseNumberAttribute, it.toDE()) }
}

private fun MDocBuilder.addItemsToSign(metaData: PidMetaData) {
    addItemToSign(IssuanceDateAttribute, metaData.issuanceDate.toKotlinLocalDate().toDE())
    addItemToSign(ExpiryDateAttribute, metaData.expiryDate.toKotlinLocalDate().toDE())
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> addItemToSign(IssuingAuthorityAttribute, issuingAuthority.code.value.toDE())
        is IssuingAuthority.AdministrativeAuthority ->
            addItemToSign(IssuingAuthorityAttribute, issuingAuthority.value.toDE())
    }
    metaData.documentNumber?.let { addItemToSign(DocumentNumberAttribute, it.value.toDE()) }
    metaData.administrativeNumber?.let { addItemToSign(AdministrativeNumberAttribute, it.value.toDE()) }
    addItemToSign(IssuingCountryAttribute, metaData.issuingCountry.value.toDE())
    metaData.issuingJurisdiction?.let { addItemToSign(IssuingJurisdictionAttribute, it.toDE()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement<*>) {
    addItemToSign(PidMsoMdocNamespace, attr.name, value)
}
