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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequestEncryption
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequestEncryptionSupportedParameters
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.serializer

context(
    _: Raise<RequestEncryptionError>,
    _: CredentialRequestEncryptionSupportedParameters,
    _: DeserializationStrategy<T>,
)
suspend fun <T> decryptWithNimbus(jwt: String): T =
    withContext(Dispatchers.Default) {
        catch({
            EncryptedJWT
                .parse(jwt)
                .ensureSupported()
                .decrypt()
                .deserialize()
        }) {
            raise(UnparseableEncryptedRequest(it))
        }
    }

context(parameters: CredentialRequestEncryptionSupportedParameters)
private fun EncryptedJWT.decrypt(): JWTClaimsSet =
    DefaultJWTProcessor<SecurityContext>()
        .apply {
            jweKeySelector =
                JWEDecryptionKeySelector(
                    header.algorithm,
                    header.encryptionMethod,
                    ImmutableJWKSet(parameters.encryptionKeys),
                )
        }.process(this, null)

context(
    _: Raise<RequestEncryptionError>,
    parameters: CredentialRequestEncryptionSupportedParameters
)
private fun EncryptedJWT.ensureSupported(): EncryptedJWT =
    apply {
        val (_, methodsSupported, compressionMethodsSupported) = parameters
        ensure(header.algorithm in parameters.algorithmsSupported) {
            UnsupportedEncryptionAlgorithm(header.algorithm, parameters.algorithmsSupported)
        }

        ensure(header.encryptionMethod in methodsSupported) {
            UnsupportedEncryptionMethod(header.encryptionMethod, methodsSupported)
        }
        header.compressionAlgorithm?.let { compressionAlgorithm ->
            ensureNotNull(compressionMethodsSupported) { RequestCompressionNotSupported }
            ensure(compressionAlgorithm in compressionMethodsSupported) {
                UnsupportedRequestCompressionMethod(compressionAlgorithm, compressionMethodsSupported)
            }
        }
    }

context(deserializer: DeserializationStrategy<T>)
private fun <T> JWTClaimsSet.deserialize(): T {
    val json = JSONObjectUtils.toJSONString(toJSONObject())
    return jsonSupport.decodeFromString(deserializer, json)
}
