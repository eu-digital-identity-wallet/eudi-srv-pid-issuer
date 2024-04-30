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

import COSE.OneKey
import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toKotlinInstant
import kotlinx.datetime.toKotlinLocalDate
import java.security.PublicKey
import java.time.Clock
import java.time.LocalDate
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class EncodeMobileDrivingLicenceInCborWithWalt(
    private val clock: Clock,
    private val validityDuration: Duration = 5.days
) : EncodeMobileDrivingLicenceInCbor {


    context(Raise<Unexpected>) override suspend fun invoke(
        licence: MobileDrivingLicence,
        holderKey: ECKey,
    ): String = try {
        val validityInfo = validityInfo(clock, validityDuration)
        val deviceKeyInfo: DeviceKeyInfo = getDeviceKeyInfo(holderKey.toPublicKey())
        with(MDocBuilder(MobileDrivingLicenceV1.docType)) {
            addItemsToSign(licence)
            val mdoc = sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, KEY_ID_ISSUER)
            mdoc.toCBORHex()
        }
    } catch (t: Throwable) {
        raise(Unexpected("Failed to encode mDL", t))
    }


    private fun getDeviceKeyInfo(deviceKey: PublicKey): DeviceKeyInfo {
        val key: OneKey = getDeviceKey(deviceKey)
        val deviceKeyDataElement: MapElement = DataElement.fromCBOR(key.AsCBOR().EncodeToBytes())
        return DeviceKeyInfo(deviceKeyDataElement, null, null)
    }

    private fun getDeviceKey(deviceKey: PublicKey): OneKey {
        return OneKey(deviceKey, null)
    }


}

private fun MDocBuilder.addItemsToSign(licence: MobileDrivingLicence) {
    addItemsToSign(licence.driver)
    addItemsToSign(licence.issueAndExpiry)
}

private fun MDocBuilder.addItemsToSign(driver: Driver) {
    addItemToSign(FamilyName, driver.familyName.latin.toDE())
    addItemToSign(GivenName, driver.givenName.latin.value.toDE())
    addItemToSign(BirthDate, driver.birthDate.toDE())
}

private fun MDocBuilder.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(IssueDate, issueAndExpiry.issuedAt.toDE())
    addItemToSign(ExpiryDate, issueAndExpiry.expiresAt.toDE())
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement<*>) {
    addItemToSign(MobileDrivingLicenceV1Namespace, attr.name, value)
}

private fun Latin150.toDE(): StringElement = StringElement(value)
private fun LocalDate.toDE(): FullDateElement = FullDateElement(this.toKotlinLocalDate())

private fun validityInfo(clock: Clock, duration: Duration): ValidityInfo {
    val signedAt = clock.instant().toKotlinInstant()
    val validTo = signedAt.plus(duration)
    return ValidityInfo(signed = signedAt, validFrom = signedAt, validUntil = validTo, expectedUpdate = null)
}

