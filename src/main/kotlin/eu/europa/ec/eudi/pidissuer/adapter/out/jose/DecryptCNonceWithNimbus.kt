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

import arrow.core.raise.result
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.port.out.jose.DecryptCNonce
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.time.Duration

/**
 * Nimbus implementation of [DecryptCNonce] that decrypts an [EncryptedJWT] as a [CNonce].
 */
internal class DecryptCNonceWithNimbus(
    private val issuer: CredentialIssuerId,
    private val decryptionKey: RSAKey,
) : DecryptCNonce {
    init {
        require(decryptionKey.isPrivate) { "a private key is required for decryption" }
    }

    private val processor = DefaultJWTProcessor<SecurityContext>()
        .apply {
            jweTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType("cnonce+jwt"))
            jweKeySelector = JWEDecryptionKeySelector(
                JWEAlgorithm.RSA_OAEP_512,
                EncryptionMethod.XC20P,
                ImmutableJWKSet(JWKSet(decryptionKey)),
            )
            jweDecrypterFactory = DefaultJWEDecrypterFactory()
                .apply {
                    jcaContext.provider = BouncyCastleProvider()
                }
            jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
                issuer.externalForm,
                JWTClaimsSet.Builder()
                    .issuer(issuer.externalForm)
                    .audience(issuer.externalForm)
                    .build(),
                setOf("iss", "aud", "cnonce", "exi", "iat"),
            )
        }

    override suspend fun invoke(encrypted: String): Result<CNonce> = result {
        val jwt = EncryptedJWT.parse(encrypted)
        val claimSet = processor.process(jwt, null)
        CNonce(
            requireNotNull(claimSet.getStringClaim("cnonce")) { "missing 'cnonce' claim" },
            requireNotNull(claimSet.issueTime.toInstant()) { "missing 'iat' claim" },
            requireNotNull(claimSet.getLongClaim("exi")?.let { Duration.ofSeconds(it) }) { "missing 'exi' claim" },
        )
    }
}
