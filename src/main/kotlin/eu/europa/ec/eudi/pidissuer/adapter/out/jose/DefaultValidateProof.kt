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

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import arrow.core.toNonEmptyListOrThrow
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidNonce
import eu.europa.ec.eudi.pidissuer.port.out.credential.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyNonce
import kotlin.time.Instant

/**
 * Validators for Proofs.
 */
internal class DefaultValidateProof(
    private val validateJwtProofWithKeyAttestation: ValidateJwtProofWithKeyAttestation,
    private val validateAttestationProof: ValidateAttestationProof,
    private val verifyNonce: VerifyNonce,
) : ValidateProof {
    context(_: Raise<IssueCredentialError>, cfg: CredentialConfiguration)
    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof?,
        at: Instant,
    ): KeyAttestation? {
        val jwtProofType = cfg.proofTypesSupported[ProofTypeEnum.JWT] as? ProofType.Jwt
        val attestationProofType = cfg.proofTypesSupported[ProofTypeEnum.ATTESTATION] as? ProofType.Attestation
        return when {
            jwtProofType == null && attestationProofType == null -> {
                ensure(unvalidatedProof == null) {
                    IssueCredentialError.InvalidProof("No proof types supported")
                }
                null
            }

            jwtProofType != null && attestationProofType != null -> {
                context(jwtProofType, attestationProofType, cfg.credentialReusePolicy, verifyNonce) {
                    val proof =
                        when (unvalidatedProof) {
                            null -> raise(IssueCredentialError.MissingProof)
                            is UnvalidatedProof.Jwt -> validateJwtProofWithKeyAttestation(unvalidatedProof, at)
                            is UnvalidatedProof.Attestation -> validateAttestationProof(unvalidatedProof, at).limitKeys()
                        }
                    proof.ensureFreshNonce(at).limitKeys()
                }
            }

            else -> {
                error("Misconfiguration: Either both Jwt and Attestation Proof Types must be supported or none of them")
            }
        }
    }
}
