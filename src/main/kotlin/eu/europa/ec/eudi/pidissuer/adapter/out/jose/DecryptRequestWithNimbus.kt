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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWEAlgorithm
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
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.serializer

internal inline fun <reified T> Raise<RequestEncryptionError>.decryptCredentialRequest(
    jwt: String,
    credentialIssuerMetadata: CredentialIssuerMetaData,
): T {
    val encryptionParameters =
        when (val requestEncryption = credentialIssuerMetadata.credentialRequestEncryption) {
            is CredentialRequestEncryption.Optional -> requestEncryption.parameters
            is CredentialRequestEncryption.Required -> requestEncryption.parameters
            is CredentialRequestEncryption.NotSupported -> raise(RequestEncryptionNotSupported)
        }
    return encryptionParameters.decrypt(this, jwt, serializer<T>())
}

private fun <T> CredentialRequestEncryptionSupportedParameters.decrypt(
    context: Raise<RequestEncryptionError>,
    jwt: String,
    deserializer: DeserializationStrategy<T>,
): T =
    context {
        fun CredentialRequestEncryptionSupportedParameters.ensureSupported(encryptedJwt: EncryptedJWT) {
            val (encryptionKeys, methodsSupported, compressionMethodsSupported) = this@ensureSupported
            val algorithmsSupported = checkNotNull(encryptionKeys.keys.map { JWEAlgorithm(it.algorithm.name) }.toNonEmptySetOrNull())

            with(encryptedJwt.header) {
                ensure(algorithm in algorithmsSupported) {
                    UnsupportedEncryptionAlgorithm(algorithm, algorithmsSupported)
                }

                ensure(encryptionMethod in methodsSupported) {
                    UnsupportedEncryptionMethod(encryptionMethod, methodsSupported)
                }
                compressionAlgorithm?.let { compressionAlgorithm ->
                    ensureNotNull(compressionMethodsSupported) {
                        RequestCompressionNotSupported
                    }
                    ensure(compressionAlgorithm in compressionMethodsSupported) {
                        UnsupportedRequestCompressionMethod(compressionAlgorithm, compressionMethodsSupported)
                    }
                }
            }
        }

        catch({
            val encryptedJwt = EncryptedJWT.parse(jwt).also { ensureSupported(it) }
            val processor = DefaultJWTProcessor<SecurityContext>()
                .apply {
                    jweKeySelector = JWEDecryptionKeySelector(
                        encryptedJwt.header.algorithm,
                        encryptedJwt.header.encryptionMethod,
                        ImmutableJWKSet(encryptionKeys),
                    )
                }

            val claims = processor.process(encryptedJwt, null)
            jsonSupport.decodeFromString(deserializer, JSONObjectUtils.toJSONString(claims.toJSONObject()))
        }) {
            raise(UnparseableEncryptedRequest(it))
        }
    }

private operator fun <T, R> Raise<T>.invoke(block: Raise<T>.() -> R): R =
    with(this) {
        block()
    }
