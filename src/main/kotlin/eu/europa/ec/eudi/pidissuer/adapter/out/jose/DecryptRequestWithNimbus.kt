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
    credentialIssuerMetadata: CredentialIssuerMetaData,
)
internal suspend inline fun <reified T> decryptCredentialRequest(jwt: String): T {
    val encryptionParameters =
        when (val requestEncryption = credentialIssuerMetadata.credentialRequestEncryption) {
            is CredentialRequestEncryption.Optional -> requestEncryption.parameters
            is CredentialRequestEncryption.Required -> requestEncryption.parameters
            is CredentialRequestEncryption.NotSupported -> raise(RequestEncryptionNotSupported)
        }
    return context(encryptionParameters, serializer<T>()) {
        decrypt(jwt)
    }
}

context(
    _: Raise<RequestEncryptionError>,
    parameters: CredentialRequestEncryptionSupportedParameters,
    deserializer: DeserializationStrategy<T>,
)
private suspend fun <T> decrypt(jwt: String): T =
    catch({
        withContext(Dispatchers.Default) {
            val encryptedJwt = EncryptedJWT.parse(jwt).apply { ensureSupported() }
            val processor =
                DefaultJWTProcessor<SecurityContext>().apply {
                    jweKeySelector =
                        JWEDecryptionKeySelector(
                            encryptedJwt.header.algorithm,
                            encryptedJwt.header.encryptionMethod,
                            ImmutableJWKSet(parameters.encryptionKeys),
                        )
                }

            val claims = processor.process(encryptedJwt, null)
            jsonSupport.decodeFromString(deserializer, JSONObjectUtils.toJSONString(claims.toJSONObject()))
        }
    }) {
        raise(UnparseableEncryptedRequest(it))
    }

context(
    _: Raise<RequestEncryptionError>,
    parameters: CredentialRequestEncryptionSupportedParameters
)
private fun EncryptedJWT.ensureSupported() {
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
