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
package eu.europa.ec.eudi.pidissuer.adapter.out.credential

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.toJavaDate
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateNonce
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Generates a Nonce and encrypts it as a [EncryptedJWT] with Nimbus.
 */
internal class GenerateNonceAndEncryptWithNimbus(
    private val issuer: CredentialIssuerId,
    private val encryptionKey: NonceEncryptionKey,
    private val generator: suspend () -> String = { Nonce(128).value },
) : GenerateNonce {

    private val encrypter = ECDHEncrypter(encryptionKey.encryptionKey)
        .apply {
            jcaContext.provider = BouncyCastleProvider()
        }

    override suspend fun invoke(generatedAt: Instant, expiresIn: Duration): String {
        val expiresAt = generatedAt + expiresIn

        return EncryptedJWT(
            JWEHeader.Builder(encryptionKey.algorithm, encryptionKey.method)
                .type(JOSEObjectType("nonce+jwt"))
                .build(),
            JWTClaimsSet.Builder()
                .apply {
                    issuer(issuer.externalForm)
                    audience(issuer.externalForm)
                    claim("nonce", generator())
                    issueTime(generatedAt.toJavaDate())
                    expirationTime(expiresAt.toJavaDate())
                }
                .build(),
        ).apply {
            encrypt(encrypter)
        }.serialize()
    }
}
