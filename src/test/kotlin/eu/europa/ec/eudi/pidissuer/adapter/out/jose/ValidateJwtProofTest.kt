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
import arrow.core.nonEmptySetOf
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
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.MobileDrivingLicenceV1
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.loadResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import kotlin.test.*

internal class ValidateJwtProofTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.systemDefaultZone()
    private val validateJwtProof = ValidateJwtProof(issuer)
    private val credentialConfiguration = MobileDrivingLicenceV1.copy(
        proofTypesSupported = ProofTypesSupported(
            nonEmptySetOf(
                ProofType.Jwt(checkNotNull(RSASSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()), KeyAttestation.NotRequired),
            ),
        ),
    )

    @Test
    internal fun `proof validation fails with incorrect 'typ'`() = runTest {
        val key = loadKey()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                type(JOSEObjectType.JWT)
                jwk(key.toPublicJWK())
            }
        val result =
            validateJwtProof(
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                credentialConfiguration,
            )

        assert(result.isLeft())
    }

    @Test
    internal fun `proof validation fails when header contains neither 'jwk' nor 'x5c'`() = runTest {
        val key = loadKey()
        val signedJwt = generateSignedJwt(key, "nonce")

        val result =
            validateJwtProof(
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                credentialConfiguration,
            )

        assert(result.isLeft())
    }

    @Test
    internal fun `proof validation fails when header contains both 'jwk' and 'x5c'`() = runTest {
        val key = loadKey()
        val chain = loadChain()
        val signedJwt = generateSignedJwt(key, "nonce") {
            jwk(key.toPublicJWK())
            x509CertChain(chain.map { Base64.encode(it.encoded) })
        }

        val result =
            validateJwtProof(
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                credentialConfiguration,
            )

        assertTrue { result.isLeft() }
    }

    @Test
    internal fun `proof validation with 'x5c' in header succeeds`() = runTest {
        val key = loadKey()
        val chain = loadChain()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                x509CertChain(chain.map { Base64.encode(it.encoded) })
            }

        validateJwtProof(
            UnvalidatedProof.Jwt(signedJwt.serialize()),
            credentialConfiguration,
        ).fold(
            ifLeft = { fail("Unexpected $it", it.cause) },
            ifRight = { credentialKey ->
                val x5c = assertIs<Pair<CredentialKey.X5c, String?>>(credentialKey, "expected 'x5c' credential key")
                assertEquals(chain, x5c.first.chain)
            },
        )
    }

    @Test
    internal fun `proof validation with 'jwk' in header succeeds`() = runTest {
        val key = loadKey()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                jwk(key.toPublicJWK())
            }

        validateJwtProof(
            UnvalidatedProof.Jwt(signedJwt.serialize()),
            credentialConfiguration,
        ).fold(
            ifLeft = { fail("Unexpected $it", it.cause) },
            ifRight = { credentialKey ->
                val jwk = assertIs<Pair<CredentialKey.Jwk, String?>>(credentialKey, "expected 'jwk' credential key")
                assertEquals(key.toPublicJWK(), jwk.first.value)
            },
        )
    }

    @Test
    internal fun `proof validation with 'kid' in header succeeds`() = runTest {
        val key = loadKey()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                keyID("did:jwk:${Base64URL.encode(key.toPublicJWK().toJSONString())}#0")
            }

        validateJwtProof(
            UnvalidatedProof.Jwt(signedJwt.serialize()),
            credentialConfiguration,
        ).fold(
            ifLeft = { fail("Unexpected $it", it.cause) },
            ifRight = { credentialKey ->
                val jwk = assertIs<Pair<CredentialKey.DIDUrl, String?>>(credentialKey, "expected 'jwk' credential key")
                assertEquals(key.toPublicJWK(), jwk.first.jwk)
            },
        )
    }

    @Test
    internal fun `proof validation fails with incorrect 'jwk' in header`() = runTest {
        val key = loadKey()
        val incorrectKey = RSAKeyGenerator(2048, false).generate()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                jwk(incorrectKey.toPublicJWK())
            }

        val result =
            validateJwtProof(
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                credentialConfiguration,
            )

        assertTrue { result.isLeft() }
    }

    @Test
    internal fun `proof validation fails with incorrect 'x5c' in header`() = runTest {
        val key = loadKey()
        val incorrectKey = RSAKeyGenerator(2048, false).generate()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                x509CertChain(incorrectKey.toPublicJWK().x509CertChain)
            }

        val result =
            validateJwtProof(
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                credentialConfiguration,
            )

        assertTrue { result.isLeft() }
    }

    @Test
    internal fun `proof validation fails with incorrect 'kid' in header`() = runTest {
        val key = loadKey()
        val incorrectKey = RSAKeyGenerator(2048, false).generate()
        val signedJwt =
            generateSignedJwt(key, "nonce") {
                keyID("did:jwk:${Base64URL.encode(incorrectKey.toPublicJWK().toJSONString())}#0")
            }
        val result =
            validateJwtProof(
                UnvalidatedProof.Jwt(signedJwt.serialize()),
                credentialConfiguration,
            )

        assertTrue { result.isLeft() }
    }

    private fun generateSignedJwt(
        key: RSAKey,
        nonce: String,
        algorithm: JWSAlgorithm = RSASSASigner.SUPPORTED_ALGORITHMS.first(),
        headersProvider: JWSHeader.Builder.() -> Unit = {},
    ): SignedJWT {
        val header = JWSHeader.Builder(algorithm)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .apply { headersProvider() }
            .build()

        val claims = JWTClaimsSet.Builder()
            .audience(issuer.externalForm)
            .issueTime(Date.from(clock.instant()))
            .claim("nonce", nonce)
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
