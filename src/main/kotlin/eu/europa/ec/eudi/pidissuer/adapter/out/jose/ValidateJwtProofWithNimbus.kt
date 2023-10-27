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

import arrow.core.NonEmptySet
import arrow.core.raise.result
import com.nimbusds.jose.*
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.ValidateJwtProof
import java.security.Key
import java.time.Duration

class ValidateJwtProofWithNimbus(private val credentialIssuerId: CredentialIssuerId) : ValidateJwtProof {
    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Jwt,
        expected: CNonce,
        supportedAlg: NonEmptySet<JWSAlgorithm>,
    ): Result<CredentialKey> = result {
        val signedJwt = SignedJWT.parse(unvalidatedProof.jwt)
        val processor = openId4VciProcessor(expected, credentialIssuerId, supportedAlg)
        processor.process(signedJwt, null)
        CredentialKey.Jwk(signedJwt.header.jwk)
    }
}

private fun openId4VciProcessor(
    expected: CNonce,
    credentialIssuerId: CredentialIssuerId,
    supportedAlg: NonEmptySet<JWSAlgorithm>,
): JWTProcessor<*> =
    DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(EXPECTED_TYPE))
        jwsKeySelector = OpenIdVCIProofSelector(supportedAlg)
        jwtClaimsSetVerifier = DefaultJWTClaimsVerifier<SecurityContext?>(
            credentialIssuerId.externalForm, // aud
            JWTClaimsSet.Builder().apply {
                claim("nonce", expected.nonce)
            }.build(),
            mutableSetOf("iat", "nonce"),

        ).apply {
            maxClockSkew = MaxClockSkew.toSecondsPart()
        }
    }

private val MaxClockSkew = Duration.ofSeconds(30)
private const val EXPECTED_TYPE = "openid4vci-proof+jwt"

private class OpenIdVCIProofSelector<C : SecurityContext?>(
    private val acceptedJWSAlgs: NonEmptySet<JWSAlgorithm>,
) : JWSKeySelector<C> {

    override fun selectJWSKeys(header: JWSHeader, context: C): MutableList<Key> {
        val alg = header.algorithm
        require(acceptedJWSAlgs.contains(alg)) { "JWS header algorithm not accepted: $alg" }

        val kid = header.keyID
        val jwk = header.jwk
        val x5c = header.x509CertChain?.let { X509CertChainUtils.parse(it).map { cert -> JWK.parse(cert) } }
        return when {
            kid != null -> TODO("Not supported")
            jwk != null -> mutableListOf(selectFromJwk(alg, jwk))
            !x5c.isNullOrEmpty() -> mutableListOf(selectFromJwk(alg, x5c[0]))
            else -> mutableListOf()
        }
    }

    private fun selectFromJwk(alg: JWSAlgorithm, jwk: JWK): Key {
        return if (JWSAlgorithm.Family.RSA.contains(alg) && jwk is RSAKey) {
            try {
                if (jwk.isPrivate) {
                    throw KeySourceException("Invalid RSA JWK: Private key is not allowed")
                }
                jwk.toRSAPublicKey()
            } catch (e: JOSEException) {
                throw KeySourceException("Invalid RSA JWK: ${e.message}", e)
            }
        } else if (JWSAlgorithm.Family.EC.contains(alg) && jwk is ECKey) {
            try {
                if (jwk.isPrivate) {
                    throw KeySourceException("Invalid RSA JWK: Private key is not allowed")
                }
                jwk.toECPublicKey()
            } catch (e: JOSEException) {
                throw KeySourceException("Invalid EC JWK: ${e.message}", e)
            }
        } else {
            throw KeySourceException("JWS header alg / jwk mismatch: alg=$alg jwk.kty=${jwk.keyType}")
        }
    }
}
