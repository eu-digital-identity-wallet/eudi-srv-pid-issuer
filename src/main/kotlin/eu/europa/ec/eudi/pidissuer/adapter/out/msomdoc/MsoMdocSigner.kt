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
package eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc

import COSE.OneKey
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.cryptoProvider
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.toKotlinInstant
import java.time.Clock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration

@OptIn(ExperimentalEncodingApi::class)
internal class MsoMdocSigner<in C>(
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val validityDuration: Duration,
    private val docType: MsoDocType,
    private val usage: MDocBuilder.(C) -> Unit,
) {

    private val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        issuerSigningKey.cryptoProvider()
    }

    suspend fun sign(cred: C, deviceKey: ECKey): String =
        withContext(Dispatchers.IO) {
            val validityInfo = validityInfo(clock, validityDuration)
            val deviceKeyInfo = getDeviceKeyInfo(deviceKey)
            val mdoc = MDocBuilder(docType)
                .apply { usage(cred) }
                .sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, issuerSigningKey.key.keyID)
            Base64.UrlSafe.encode(mdoc.toCBOR())
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
