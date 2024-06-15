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

import arrow.core.NonEmptyList
import arrow.core.raise.either
import arrow.core.toNonEmptyListOrNull
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.loadResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import kotlin.test.*
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@OptIn(ExperimentalCoroutinesApi::class)
internal class ValidateJwtProofTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.systemDefaultZone()

    @Test
    internal fun `proof validation fails with incorrect 'typ'`() = runTest {
        val key = loadKey()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                type(JOSEObjectType.JWT)
                jwk(key.toPublicJWK())
            }
        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        val result = either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }
        assert(result.isLeft())
    }

    @Test
    internal fun `proof validation fails when header contains neither 'jwk' nor 'x5c'`() = runTest {
        val key = loadKey()
        val nonce = generateCNonce()
        val signedJwt = generateSignedJwt(key, nonce)

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        val result = either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }
        assert(result.isLeft())
    }

    @Test
    internal fun `proof validation fails when header contains both 'jwk' and 'x5c'`() = runTest {
        val key = loadKey()
        val chain = loadChain()
        val nonce = generateCNonce()
        val signedJwt = generateSignedJwt(key, nonce) {
            jwk(key.toPublicJWK())
            x509CertChain(chain.map { Base64.encode(it.encoded) })
        }

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        val result = either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }
        assertTrue { result.isLeft() }
    }

    @Test
    internal fun `proof validation with 'x5c' in header succeeds`() = runTest {
        val key = loadKey()
        val chain = loadChain()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                x509CertChain(chain.map { Base64.encode(it.encoded) })
            }

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))

        either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }.fold(
            ifLeft = { fail("Unexpected $it") },
            ifRight = { credentialKey ->
                val x5c = assertIs<CredentialKey.X5c>(credentialKey, "expected 'x5c' credential key")
                assertEquals(chain, x5c.chain)
            },
        )
    }

    @Test
    internal fun `proof validation with 'jwk' in header succeeds`() = runTest {
        val key = loadKey()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                jwk(key.toPublicJWK())
            }

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }.fold(
            ifLeft = { fail("Unexpected $it") },
            ifRight = { credentialKey ->
                val jwk = assertIs<CredentialKey.Jwk>(credentialKey, "expected 'jwk' credential key")
                assertEquals(key.toPublicJWK(), jwk.value)
            },
        )
    }

    @Test
    internal fun `proof validation with 'kid' in header succeeds`() = runTest {
        val key = loadKey()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                keyID("did:jwk:${Base64URL.encode(key.toPublicJWK().toJSONString())}#0")
            }

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }.fold(
            ifLeft = { fail("Unexpected $it") },
            ifRight = { credentialKey ->
                val jwk = assertIs<CredentialKey.DIDUrl>(credentialKey, "expected 'jwk' credential key")
                assertEquals(key.toPublicJWK(), jwk.jwk)
            },
        )
    }

    @Test
    internal fun `proof validation fails with incorrect 'jwk' in header`() = runTest {
        val key = loadKey()
        val incorrectKey = RSAKeyGenerator(2048, false).generate()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                jwk(incorrectKey.toPublicJWK())
            }

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        val result = either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }
        assertTrue { result.isLeft() }
    }

    @Test
    internal fun `proof validation fails with incorrect 'x5c' in header`() = runTest {
        val key = loadKey()
        val incorrectKey = RSAKeyGenerator(2048, false).generate()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                x509CertChain(incorrectKey.toPublicJWK().x509CertChain)
            }

        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))
        val result = either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }
        assertTrue { result.isLeft() }
    }

    @Test
    internal fun `proof validation fails with incorrect 'kid' in header`() = runTest {
        val key = loadKey()
        val incorrectKey = RSAKeyGenerator(2048, false).generate()
        val nonce = generateCNonce()
        val signedJwt =
            generateSignedJwt(key, nonce) {
                keyID("did:jwk:${Base64URL.encode(incorrectKey.toPublicJWK().toJSONString())}#0")
            }
        val proofType = ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()))

        val result = either {
            validateJwtProof(
                issuer,
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                nonce,
                proofType,
            )
        }
        assertTrue { result.isLeft() }
    }

    private fun generateCNonce(): CNonce =
        CNonce(
            UUID.randomUUID().toString(),
            UUID.randomUUID().toString(),
            clock.instant(),
            5.minutes.toJavaDuration(),
        )

    private fun generateSignedJwt(
        key: RSAKey,
        nonce: CNonce,
        algorithm: JWSAlgorithm = RSASSASigner.SUPPORTED_ALGORITHMS.first(),
        headersProvider: JWSHeader.Builder.() -> Unit = {},
    ): SignedJWT {
        val header = JWSHeader.Builder(algorithm)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .apply { headersProvider() }
            .build()

        val claims = JWTClaimsSet.Builder()
            .audience(issuer.externalForm)
            .issueTime(Date.from(nonce.activatedAt))
            .expirationTime(Date.from(nonce.activatedAt + nonce.expiresIn))
            .claim("nonce", nonce.nonce)
            .build()

        return SignedJWT(header, claims).apply { sign(RSASSASigner(key)) }
    }
}

private suspend fun loadChain(): NonEmptyList<X509Certificate> =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/Chain.pem")
            .readText()
            .let {
                X509CertChainUtils.parse(it)
            }
            .let {
                assertEquals(3, it.size, "expected 3 certificates in the chain")
                assertNotNull(it.toNonEmptyListOrNull())
            }
    }

private suspend fun loadKey(): RSAKey =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/Key.key")
            .readText()
            .let {
                RSAKey.parseFromPEMEncodedObjects(it).toRSAKey()
            }
    }
