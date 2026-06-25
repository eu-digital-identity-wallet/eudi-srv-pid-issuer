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

import arrow.core.getOrElse
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid.pidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.adapter.out.proof.ValidateAttestationProof
import eu.europa.ec.eudi.pidissuer.adapter.out.proof.ValidateJwtProofWithKeyAttestation
import eu.europa.ec.eudi.pidissuer.adapter.out.proof.VerifyKeyAttestation
import eu.europa.ec.eudi.pidissuer.adapter.out.trust.Ignored
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.jwtProof
import eu.europa.ec.eudi.pidissuer.keyAttestationJWT
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedKeyAttestationIssuer
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

class DefaultValidateProofTest {
    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.System
    private val verifyKeyAttestation =
        VerifyKeyAttestation(isTrustedKeyAttestationIssuer = IsTrustedKeyAttestationIssuer.Ignored)

    @Test
    internal fun `keys are not truncated when reuse policy is None`() =
        runTest {
            // 1 signing key + 1 extra key in attestation = 2 attested keys
            val proof = generateJwtProofWithAttestation(extraKeysNo = 1)
            val result =
                runValidateProofs(
                    proof = proof,
                    policy = CredentialReusePolicy.None,
                )

            // 2 attested keys, all distinct, none truncated
            assertEquals(2, result?.keys?.value?.size)
        }

    @Test
    internal fun `keys are truncated to 1 when reuse policy contains LimitedTime`() =
        runTest {
            // 1 signing key + 1 extra key in attestation = 2 attested keys
            val proof = generateJwtProofWithAttestation(extraKeysNo = 1)
            val policy =
                CredentialReusePolicy.EUDI(
                    id = "test",
                    options = listOf(EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft = 5.minutes)),
                )
            val result =
                runValidateProofs(
                    proof = proof,
                    policy = policy,
                )

            assertEquals(1, result?.keys?.value?.size)
        }

    @Test
    internal fun `keys are truncated to effective batch size`() =
        runTest {
            // Single proof carrying 5 keys (1 signing + 4 extra)
            val proof = generateJwtProofWithAttestation(extraKeysNo = 4)
            val policy =
                CredentialReusePolicy.EUDI(
                    id = "test",
                    options = listOf(EudiReusePolicy.OnceOnly(batchSize = 3, reissueTriggerUnused = 1)),
                )
            val result =
                runValidateProofs(
                    proof = proof,
                    policy = policy,
                )

            assertEquals(3, result?.keys?.value?.size)
        }

    private suspend fun runValidateProofs(
        proof: Pair<UnvalidatedProof.Jwt, *>,
        policy: CredentialReusePolicy,
    ): KeyAttestation? {
        val (unvalidatedProof, _) = proof

        val validator =
            ValidateProof(
                validateJwtProofWithKeyAttestation = ValidateJwtProofWithKeyAttestation(issuer, verifyKeyAttestation),
                validateAttestationProof = ValidateAttestationProof(verifyKeyAttestation),
                verifyNonce = { _, _ -> true },
            )

        val configuration =
            pidMsoMdocV1(
                CoseAlgorithm(-7),
                deviceBinding =
                    DeviceBinding.Required(
                        nonEmptySetOf(JWSAlgorithm.ES256),
                        KeyAttestationRequirement(
                            keyStorage = nonEmptySetOf(AttackPotentialResistance.Iso18045EnhancedBasic),
                            userAuthentication = nonEmptySetOf(AttackPotentialResistance.Iso18045EnhancedBasic),
                            preferredKeyStorageStatusPeriod = PreferredKeyStorageStatusPeriod(31.days),
                        ),
                    ),
                credentialReusePolicy = policy,
                validity = 365.days,
            )

        return context(configuration) {
            either { validator(unvalidatedProof, clock.now()) } getOrElse { fail("Expected success but got $it") }
        }
    }

    private suspend fun generateJwtProofWithAttestation(extraKeysNo: Int): Pair<UnvalidatedProof.Jwt, ECKey> {
        val clock = Clock.System
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val keyAttestationJwt =
            keyAttestationJWT(
                proofSigningKey = jwtProofSigningKey,
                keyStorageConstraints = listOf("iso_18045_enhanced-basic"),
                userAuthorizationConstraints = listOf("iso_18045_enhanced-basic"),
                clock = clock,
            ) {
                (0..<extraKeysNo).map {
                    ECKeyGenerator(Curve.P_256).generate()
                }
            }

        val signed =
            jwtProof(issuer, clock, "nonce", jwtProofSigningKey) {
                customParam("key_attestation", keyAttestationJwt.serialize())
            }
        return UnvalidatedProof.Jwt(signed.serialize()) to jwtProofSigningKey
    }
}
