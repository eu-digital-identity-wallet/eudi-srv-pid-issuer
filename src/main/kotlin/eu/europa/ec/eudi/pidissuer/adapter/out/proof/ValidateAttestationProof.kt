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
package eu.europa.ec.eudi.pidissuer.adapter.out.proof

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.effect
import arrow.core.raise.fold
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import kotlin.time.Instant

class ValidateAttestationProof(
    private val verifyKeyAttestation: VerifyKeyAttestation,
) : ValidateProof.Validator<UnvalidatedProof.Attestation, ProofType.Attestation> {
    context(_: Raise<IssueCredentialError.InvalidProof>, proofType: ProofType.Attestation)
    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Attestation,
        at: Instant,
    ): KeyAttestation =
        effect {
            KeyAttestationJWT(unvalidatedProof.jwt).checkAlg().keyAttestation(at)
        }.fold(
            transform = { it },
            recover = { raise(IssueCredentialError.InvalidProof(it)) },
            catch = { raise(IssueCredentialError.InvalidProof("Invalid proof Attestation", it)) },
        )

    context(_: Raise<String>, proofType: ProofType.Attestation)
    private fun KeyAttestationJWT.checkAlg() =
        apply {
            val alg = jwt.header.algorithm
            ensure(alg in proofType.signingAlgorithmsSupported) {
                val supported = proofType.signingAlgorithmsSupported.joinToString(", ") { it.name }
                "Key attestation signing algorithm '$alg' is not supported, must be one of: $supported"
            }
        }

    context(_: Raise<String>, proofType: ProofType.Attestation)
    private suspend fun KeyAttestationJWT.keyAttestation(at: Instant): KeyAttestation {
        val (attestedKeys, nonce) = verifyKeyAttestation(this, at)
        ensureNotNull(nonce) { "Key attestation does not contain a c_nonce." }
        ensure(
            claims.keyStorageStatus.exp >= at + proofType.keyAttestationRequirement.preferredKeyStorageStatusPeriod.value,
        ) {
            "Key Storage Status expiration date does not meet the preferred key storage status period"
        }

        return KeyAttestation(
            keys = CredentialKeys(attestedKeys),
            cNonce = nonce,
            keyStorageStatus = claims.keyStorageStatus,
        )
    }
}
