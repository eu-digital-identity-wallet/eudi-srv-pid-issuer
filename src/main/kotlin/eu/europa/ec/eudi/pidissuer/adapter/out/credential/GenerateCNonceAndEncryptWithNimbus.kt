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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateCNonce
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.time.Clock
import java.time.Duration
import java.util.*

/**
 * Generates a CNonce and encrypts it as a [EncryptedJWT] with Nimbus.
 */
internal class GenerateCNonceAndEncryptWithNimbus(
    private val clock: Clock,
    private val issuer: CredentialIssuerId,
    encryptionKey: RSAKey,
    private val generator: suspend () -> String = { Nonce(128).value },
) : GenerateCNonce {

    private val encrypter = RSAEncrypter(encryptionKey)
        .apply {
            jcaContext.provider = BouncyCastleProvider()
        }

    override suspend fun invoke(cnonceExpiresIn: Duration): String {
        val issuedAt = clock.instant()
        val expiresAt = issuedAt + cnonceExpiresIn

        return EncryptedJWT(
            JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_512, EncryptionMethod.XC20P)
                .type(JOSEObjectType("cnonce+jwt"))
                .build(),
            JWTClaimsSet.Builder()
                .apply {
                    issuer(issuer.externalForm)
                    audience(issuer.externalForm)
                    claim("cnonce", generator())
                    issueTime(Date.from(issuedAt))
                    expirationTime(Date.from(expiresAt))
                }
                .build(),
        ).apply {
            encrypt(encrypter)
        }.serialize()
    }
}
