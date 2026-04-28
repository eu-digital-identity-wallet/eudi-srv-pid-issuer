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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.adapter.out.trust.Ignored
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.CoseAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialReusePolicy
import eu.europa.ec.eudi.pidissuer.domain.EudiReusePolicy
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestationRequirement
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.domain.toJavaDate
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedKeyAttestationIssuer
import kotlinx.coroutines.test.runTest
import kotlin.test.*
import kotlin.time.Duration.Companion.minutes

class ValidateProofTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.System
    private val verifyKeyAttestation = VerifyKeyAttestation(isTrustedKeyAttestationIssuer = IsTrustedKeyAttestationIssuer.Ignored)
    private val validateProofs = ValidateProofs(
        validateJwtProof = ValidateJwtProof(issuer, verifyKeyAttestation),
        validateAttestationProof = ValidateAttestationProof(verifyKeyAttestation),
        verifyNonce = { _, _ ->
            fail("VerifyCNonce should not have been invoked")
        },
        extractJwkFromCredentialKey = { _ ->
            fail("ExtractJwkFromCredentialKey should not have been invoked.")
        },
    )

    @Test
    internal fun `fails with unsupported proof type`() = runTest {
        val proof = UnvalidatedProof.DiVp("foo")

        val result =
            validateProofs(
                nonEmptyListOf(proof),
                pidMsoMdocV1(
                    CoseAlgorithm(-7),
                    nonEmptySetOf(JWSAlgorithm.ES256),
                    KeyAttestationRequirement.NotRequired,
                ),
                clock.now(),
            )

        assert(result.isLeft())

        val error = assertIs<IssueCredentialError.InvalidProof>(result.leftOrNull())
        assertEquals("Supporting only JWT proof", error.msg)
        assertNull(error.cause)
    }

    @Test
    internal fun `keys are not truncated when reuse policy is None`() = runTest {
        val proofs = generateJwtProofs(3)
        val result = runValidateProofsKeepingAllKeys(
            proofs = proofs,
            extraKeysPerProof = { listOf(generateJwk()) },
            policy = CredentialReusePolicy.None,
        )

        // 3 proofs * (1 main + 1 extra unique) = 6 keys, all distinct, none truncated
        assertEquals(6, result.size)
    }

    @Test
    internal fun `keys are truncated to 1 when reuse policy contains LimitedTime`() = runTest {
        val proofs = generateJwtProofs(2)
        val policy = CredentialReusePolicy.EUDI(
            id = "test",
            options = listOf(EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft = 5.minutes)),
        )
        val result = runValidateProofsKeepingAllKeys(
            proofs = proofs,
            extraKeysPerProof = { listOf(generateJwk()) },
            policy = policy,
        )

        assertEquals(1, result.size)
    }

    @Test
    internal fun `keys are truncated to effective batch size`() = runTest {
        // Single proof carrying 5 keys (e.g. attestation proof)
        val proofs = generateJwtProofs(1)
        val extras = (1..4).map { generateJwk() }
        val policy = CredentialReusePolicy.EUDI(
            id = "test",
            options = listOf(EudiReusePolicy.OnceOnly(batchSize = 3, reissueTriggerUnused = 1)),
        )
        val result = runValidateProofsKeepingAllKeys(
            proofs = proofs,
            extraKeysPerProof = { extras },
            policy = policy,
        )

        assertEquals(3, result.size)
    }

    @Test
    internal fun `truncation spans multiple proofs`() = runTest {
        // 4 proofs, each contributing 1 key => 4 distinct keys
        val proofs = generateJwtProofs(4)
        val policy = CredentialReusePolicy.EUDI(
            id = "test",
            options = listOf(EudiReusePolicy.OnceOnly(batchSize = 2, reissueTriggerUnused = 1)),
        )
        val result = runValidateProofsKeepingAllKeys(
            proofs = proofs,
            extraKeysPerProof = { emptyList() },
            policy = policy,
        )

        assertEquals(2, result.size)
    }

    private suspend fun runValidateProofsKeepingAllKeys(
        proofs: NonEmptyList<Pair<UnvalidatedProof.Jwt, ECKey>>,
        extraKeysPerProof: () -> List<JWK>,
        policy: CredentialReusePolicy,
    ): NonEmptyList<JWK> {
        val keysByProofKey = proofs.associate { (_, key) ->
            key.toPublicJWK().computeThumbprint().toString() to
                checkNotNull((listOf<JWK>(key.toPublicJWK()) + extraKeysPerProof()).toNonEmptyListOrNull())
        }

        val extract = ExtractJwkFromCredentialKey { credentialKey ->
            // For our generated proofs the credential key is always a Jwk; look it up by thumbprint
            val jwk = (credentialKey as eu.europa.ec.eudi.pidissuer.domain.CredentialKey.Jwk).value
            val match = keysByProofKey[jwk.computeThumbprint().toString()]
                ?: error("Unexpected credential key in test")
            Either.Right<NonEmptyList<JWK>>(match)
        }

        val validator = ValidateProofs(
            validateJwtProof = ValidateJwtProof(issuer, verifyKeyAttestation),
            validateAttestationProof = ValidateAttestationProof(verifyKeyAttestation),
            verifyNonce = { _, _ -> true },
            extractJwkFromCredentialKey = extract,
        )

        val configuration = pidMsoMdocV1(
            CoseAlgorithm(-7),
            nonEmptySetOf(JWSAlgorithm.ES256),
            KeyAttestationRequirement.NotRequired,
            credentialReusePolicy = policy,
        )

        val result = validator(
            checkNotNull(proofs.map { it.first }.toNonEmptyListOrNull()),
            configuration,
            clock.now(),
        )
        return result.fold({ fail("Expected success but got $it") }, { it })
    }

    private fun generateJwtProofs(count: Int): NonEmptyList<Pair<UnvalidatedProof.Jwt, ECKey>> {
        val list = (1..count).map {
            val key = generateEcKey()
            val signed = SignedJWT(
                JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType("openid4vci-proof+jwt"))
                    .jwk(key.toPublicJWK())
                    .build(),
                JWTClaimsSet.Builder()
                    .audience(issuer.externalForm)
                    .issueTime(clock.now().toJavaDate())
                    .claim("nonce", "nonce")
                    .build(),
            ).apply { sign(ECDSASigner(key)) }
            UnvalidatedProof.Jwt(signed.serialize()) to key
        }
        return checkNotNull(list.toNonEmptyListOrNull())
    }

    private fun generateEcKey(): ECKey =
        ECKeyGenerator(Curve.P_256).generate()

    private fun generateJwk(): JWK =
        ECKeyGenerator(Curve.P_256).generate().toPublicJWK()
}
