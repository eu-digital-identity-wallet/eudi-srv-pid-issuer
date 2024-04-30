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

import COSE.AlgorithmID
import COSE.OneKey
import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toKotlinInstant
import kotlinx.datetime.toKotlinLocalDate
import java.security.KeyPair
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.LocalDate
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class EncodeMobileDrivingLicenceInCborWithWalt(
    private val clock: Clock,
    private val issuerKey: ECKey,
    private val issuerKeyId: String,
    private val validityDuration: Duration = 5.days,
) : EncodeMobileDrivingLicenceInCbor {

    val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        TODO()
    }

    context(Raise<Unexpected>) override suspend fun invoke(
        licence: MobileDrivingLicence,
        holderKey: ECKey,
    ): String = try {
        val validityInfo = validityInfo(clock, validityDuration)
        val deviceKeyInfo: DeviceKeyInfo = getDeviceKeyInfo(holderKey.toPublicKey())
        with(MDocBuilder(MobileDrivingLicenceV1.docType)) {
            addItemsToSign(licence)
            val mdoc = sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, issuerKeyId)
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

    fun issuerCryptoProvider(
        issuerKey: KeyPair,
        issuerCertificateChain: List<X509Certificate?>?,
    ): SimpleCOSECryptoProvider {
        val publicKey = issuerKey.public
        if (publicKey is ECPublicKey) {
            return SimpleCOSECryptoProvider(
                java.util.List.of<COSECryptoProviderKeyInfo>(
                    COSECryptoProviderKeyInfo(
                        keyID = issuerKeyId,
                        getAlgorithmId(publicKey),
                        publicKey,
                        issuerKey.private,
                        emptyList(),
                        emptyList<X509Certificate>(),
                    ),
                ),
            )
        } else {
            throw IllegalArgumentException("Invalid key type. An Elliptic Curve key is required by ISO/IEC 18013-5:2021.")
        }
    }

    private fun getAlgorithmId(ecPublicKey: ECPublicKey): AlgorithmID {
        val bitLength = ecPublicKey.params.order.bitLength()
        return when (bitLength) {
            256 -> AlgorithmID.ECDSA_256
            384 -> AlgorithmID.ECDSA_384
            521 -> AlgorithmID.ECDSA_512
            else -> throw IllegalArgumentException("Unsupported key size: $bitLength")
        }
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
