/*
 * Copyright (c) 2023-2026 European Commission
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

import arrow.core.*
import arrow.core.raise.either
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.mobileDrivingLicenceV1
import eu.europa.ec.eudi.pidissuer.adapter.out.trust.Ignored
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.loadResource
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedKeyAttestationIssuer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

internal class ValidateJwtProofWithKeyAttestationTest {
    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.System
    private val verifyKeyAttestation =
        VerifyKeyAttestation(isTrustedKeyAttestationIssuer = IsTrustedKeyAttestationIssuer.Ignored)
    private val validateJwtProofWithKeyAttestation = ValidateJwtProofWithKeyAttestation(issuer, verifyKeyAttestation)
    private val credentialConfiguration =
        mobileDrivingLicenceV1(
            CoseAlgorithm(-7),
            deviceBinding =
                DeviceBinding.Required(
                    checkNotNull(ECDSASigner.SUPPORTED_ALGORITHMS.toNonEmptySetOrNull()),
                    KeyAttestationRequirement.ts3(PreferredKeyStorageStatusPeriod(60.days)),
                ),
            validity = 24.hours,
        )

    private val supported =
        credentialConfiguration.deviceBinding
            .proofTypesSupported()
            .filterIsInstance<ProofType.Jwt>()
            .first()

    @Test
    internal fun `proof validation fails with incorrect 'typ'`() =
        runTest {
            val key = loadKey()
            val signedJwt =
                generateSignedJwt(key, "nonce") {
                    type(JOSEObjectType.JWT)
                    jwk(key.toPublicJWK())
                }
            context(supported) {
                either {
                    validateJwtProofWithKeyAttestation(
                        UnvalidatedProof.Jwt(signedJwt.serialize()),
                        clock.now(),
                    )
                }.swap().getOrElse {
                    fail("Expected failure but got $it")
                }
            }
        }

    @Test
    internal fun `proof validation fails when header contains neither 'jwk' nor 'x5c'`() =
        runTest {
            val key = loadKey()
            val signedJwt = generateSignedJwt(key, "nonce")
            context(supported) {
                either {
                    validateJwtProofWithKeyAttestation(
                        UnvalidatedProof.Jwt(signedJwt.serialize()),
                        clock.now(),
                    )
                }.swap() getOrElse {
                    fail("Expected failure but got $it")
                }
            }
        }

    @Test
    internal fun `proof validation fails when header contains both 'jwk' and 'x5c'`() =
        runTest {
            val key = loadKey()
            val chain = loadChain()
            val signedJwt =
                generateSignedJwt(key, "nonce") {
                    jwk(key.toPublicJWK())
                    x509CertChain(chain.map { Base64.encode(it.encoded) })
                }

            context(supported) {
                either { validateJwtProofWithKeyAttestation(UnvalidatedProof.Jwt(signedJwt.serialize()), clock.now()) }
                    .swap()
                    .getOrElse { fail("Expected failure but got $it") }
            }
        }

    @Test
    internal fun `proof validation fails with incorrect 'jwk' in header`() =
        runTest {
            val key = loadKey()
            val incorrectKey = RSAKeyGenerator(2048, false).generate()
            val signedJwt =
                generateSignedJwt(key, "nonce") {
                    jwk(incorrectKey.toPublicJWK())
                }

            context(supported) {
                either { validateJwtProofWithKeyAttestation(UnvalidatedProof.Jwt(signedJwt.serialize()), clock.now()) }
                    .swap()
                    .getOrElse { fail("Expected failure but got $it") }
            }
        }

    @Test
    internal fun `proof validation fails with incorrect 'x5c' in header`() =
        runTest {
            val key = loadKey()
            val incorrectKey = RSAKeyGenerator(2048, false).generate()
            val signedJwt =
                generateSignedJwt(key, "nonce") {
                    x509CertChain(incorrectKey.toPublicJWK().x509CertChain)
                }

            context(supported) {
                either { validateJwtProofWithKeyAttestation(UnvalidatedProof.Jwt(signedJwt.serialize()), clock.now()) }
                    .swap()
                    .getOrElse { fail("Expected failure but got $it") }
            }
        }

    @Test
    internal fun `proof validation fails with incorrect 'kid' in header`() =
        runTest {
            val key = loadKey()
            val incorrectKey = RSAKeyGenerator(2048, false).generate()
            val signedJwt =
                generateSignedJwt(key, "nonce") {
                    keyID("did:jwk:${Base64URL.encode(incorrectKey.toPublicJWK().toJSONString())}#0")
                }
            context(supported) {
                either { validateJwtProofWithKeyAttestation(UnvalidatedProof.Jwt(signedJwt.serialize()), clock.now()) }
                    .swap()
                    .getOrElse { fail("Expected failure but got $it") }
            }
        }

    @Test
    internal fun `proof validation fails with unsupported 'alg' in header`() =
        runTest {
            val key = loadKey()
            val signedJwt =
                generateSignedJwt(key, "nonce") {
                    jwk(key.toPublicJWK())
                }

            val credentialConfiguration =
                mobileDrivingLicenceV1(
                    CoseAlgorithm(-7),
                    DeviceBinding.Required(
                        nonEmptySetOf(JWSAlgorithm.ES512),
                        KeyAttestationRequirement.ts3(PreferredKeyStorageStatusPeriod(60.days)),
                    ),
                    validity = 24.hours,
                )

            val supported =
                credentialConfiguration.deviceBinding
                    .proofTypesSupported()
                    .filterIsInstance<ProofType.Jwt>()
                    .first()
            context(supported) {
                either { validateJwtProofWithKeyAttestation(UnvalidatedProof.Jwt(signedJwt.serialize()), clock.now()) }
                    .swap()
                    .getOrElse { fail("Expected failure but got $it") }
            }
        }

    private fun generateSignedJwt(
        key: ECKey,
        nonce: String,
        algorithm: JWSAlgorithm = ECDSASigner.SUPPORTED_ALGORITHMS.first(),
        headersProvider: JWSHeader.Builder.() -> Unit = {},
    ): SignedJWT {
        val header =
            JWSHeader
                .Builder(algorithm)
                .type(JOSEObjectType("openid4vci-proof+jwt"))
                .apply { headersProvider() }
                .build()

        val claims =
            JWTClaimsSet
                .Builder()
                .audience(issuer.externalForm)
                .issueTime(clock.now().toJavaDate())
                .claim("nonce", nonce)
                .build()

        return SignedJWT(header, claims).apply { sign(ECDSASigner(key)) }
    }
}

private suspend fun loadChain(): NonEmptyList<X509Certificate> =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/Chain.pem")
            .readText()
            .let {
                X509CertChainUtils.parse(it)
            }.let {
                assertEquals(3, it.size, "expected 3 certificates in the chain")
                assertNotNull(it.toNonEmptyListOrNull())
            }
    }

private suspend fun loadKey(): ECKey =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/Key.key")
            .readText()
            .let {
                ECKey.parseFromPEMEncodedObjects(it).toECKey()
            }
    }
