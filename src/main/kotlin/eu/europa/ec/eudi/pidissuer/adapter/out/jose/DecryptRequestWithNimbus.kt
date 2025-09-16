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

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequestEncryption
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.*

internal inline fun <reified T> Raise<RequestEncryptionError>.decryptCredentialRequest(
    jwt: String,
    credentialIssuerMetadata: CredentialIssuerMetaData,
): T {
    val encryptedJwt = Either.catch {
        EncryptedJWT.parse(jwt)
    }.mapLeft { UnparseableEncryptedRequest(it) }
        .bind()
    val (encryptionKeys, methodsSupported, compressionMethodsSupported) =
        when (val requestEncryption = credentialIssuerMetadata.credentialRequestEncryption) {
            is CredentialRequestEncryption.Optional -> {
                requestEncryption.parameters
            }
            is CredentialRequestEncryption.Required -> {
                requestEncryption.parameters
            }
            is CredentialRequestEncryption.NotSupported -> raise(RequestEncryptionNotSupported)
        }

    ensure(methodsSupported.any { it == encryptedJwt.header.encryptionMethod }) {
        UnsupportedEncryptionMethod(encryptedJwt.header.encryptionMethod, methodsSupported)
    }
    encryptedJwt.header.compressionAlgorithm?.let { compressionAlgorithm ->
        ensureNotNull(compressionMethodsSupported) {
            RequestCompressionNotSupported
        }
        ensure(compressionMethodsSupported.any { it.name == compressionAlgorithm.name }) {
            UnsupportedRequestCompressionMethod(encryptedJwt.header.compressionAlgorithm, compressionMethodsSupported)
        }
    }

    val processor = DefaultJWTProcessor<SecurityContext>()
    processor.jweKeySelector = JWEDecryptionKeySelector(
        encryptedJwt.header.algorithm,
        encryptedJwt.header.encryptionMethod,
        ImmutableJWKSet(encryptionKeys),
    )
    val claims = processor.process(encryptedJwt, null)
    return jsonSupport.decodeFromString<T>(JSONObjectUtils.toJSONString(claims.toJSONObject()))
}
