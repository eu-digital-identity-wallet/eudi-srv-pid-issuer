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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCNonce
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.util.*

/**
 * Nimbus implementation of [EncryptCNonce] that encrypts [CNonce] as an [EncryptedJWT].
 */
internal class EncryptCNonceWithNimbus(
    private val issuer: CredentialIssuerId,
    private val signingKey: IssuerSigningKey,
    encryptionKey: RSAKey,
) : EncryptCNonce {

    private val jcaProvider = BouncyCastleProvider()
    private val signer = run {
        val factory = DefaultJWSSignerFactory().apply { jcaContext.provider = jcaProvider }
        factory.createJWSSigner(signingKey.key, signingKey.signingAlgorithm)
    }
    private val encrypter = RSAEncrypter(encryptionKey).apply { jcaContext.provider = jcaProvider }

    override suspend fun invoke(cnonce: CNonce): String {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(signingKey.signingAlgorithm)
                .type(JOSEObjectType("cnonce+jwt"))
                .build(),
            JWTClaimsSet.Builder()
                .apply {
                    issuer(issuer.externalForm)
                    audience(issuer.externalForm)
                    claim("cnonce", cnonce.nonce)
                    claim("exi", cnonce.expiresIn.seconds)
                    issueTime(Date.from(cnonce.activatedAt))
                    expirationTime(Date.from((cnonce.activatedAt + cnonce.expiresIn)))
                }
                .build(),
        ).apply {
            sign(signer)
        }

        val encryptedJwt = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_512, EncryptionMethod.XC20P)
                .type(JOSEObjectType("cnonce+jwt"))
                .contentType("JWT")
                .build(),
            Payload(signedJwt),
        ).apply {
            encrypt(encrypter)
        }

        return encryptedJwt.serialize()
    }
}
