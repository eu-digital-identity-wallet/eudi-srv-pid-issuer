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
import arrow.core.NonEmptySet
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
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
import eu.europa.ec.eudi.pidissuer.port.out.jose.ValidateJwtProof
import java.security.Key
import java.time.Duration

class ValidateJwtProofWithNimbus(private val ctx: CredentialIssuerContext) : ValidateJwtProof {
    override fun invoke(
        jwtProof: SignedJWT,
        expected: CNonce,
        meta: CredentialMetaData,
    ): Either<Throwable, CredentialKey> =
        TODO()
//        either {
//            Either.catch { processor(expected, ctx.metaData.id, meta.cryptographicBindingMethodsSupported.).process(jwtProof, null) }.bind()
//            withError({ error -> IllegalArgumentException(error) }) {
//                credentialKey(jwtProof.header).bind()
//            }
//        }
}

private fun credentialKey(jwsHeader: JWSHeader): Either<String, CredentialKey> = either {
    fun JWSAlgorithm.isAsymmetric(): Boolean = JWSAlgorithm.Family.SIGNATURE.contains(this)
    val alg = jwsHeader.algorithm
    ensureNotNull(alg) { "Missing alg" }
    ensure(alg.isAsymmetric()) { "Alg $alg is not asymmetric." }
    ensure(jwsHeader.type == JOSEObjectType(EXPECTED_TYPE)) { "Wrong typ ${jwsHeader.type.type}. Was expecting `$EXPECTED_TYPE`" }
    val jwk = jwsHeader.jwk
    val kid = jwsHeader.keyID
    val x5c = jwsHeader.x509CertChain?.let {
        Either.catch { X509CertChainUtils.parse(it).toList() }.mapLeft { t -> "X509 change Parsing exception" }.bind()
    }

    when {
        kid != null && jwk == null && x5c == null -> CredentialKey.DIDUrl(kid)
        kid == null && jwk != null && x5c == null -> CredentialKey.Jwk(jwk)
        kid == null && jwk != null && x5c != null -> CredentialKey.X5c(x5c)
        else -> raise("Unable to extract pub key form proof header")
    }
}

private fun processor(
    expected: CNonce,
    credentialIssuerId: CredentialIssuerId,
    keySelector: JWSKeySelector<SecurityContext>,
): JWTProcessor<*> =
    DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(EXPECTED_TYPE))
        jwsKeySelector = keySelector
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

private class PIdJwsKeySelector<C : SecurityContext?>(
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
