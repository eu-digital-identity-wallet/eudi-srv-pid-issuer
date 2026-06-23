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
package eu.europa.ec.eudi.pidissuer.port.out.proof

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialReusePolicy
import eu.europa.ec.eudi.pidissuer.domain.DeviceBinding
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestation
import eu.europa.ec.eudi.pidissuer.domain.ProofType
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.domain.ensureFreshNonce
import eu.europa.ec.eudi.pidissuer.domain.limitKeys
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.nonce.VerifyNonce
import kotlin.time.Instant

class ValidateProof(
    private val validateJwtProofWithKeyAttestation: Validator<UnvalidatedProof.Jwt, ProofType.Jwt>,
    private val validateAttestationProof: Validator<UnvalidatedProof.Attestation, ProofType.Attestation>,
    private val verifyNonce: VerifyNonce,
) {
    fun interface Validator<in UP : UnvalidatedProof, in PT : ProofType> {
        context(_: Raise<IssueCredentialError.InvalidProof>, proofType: PT)
        suspend operator fun invoke(
            unvalidatedProof: UP,
            at: Instant,
        ): KeyAttestation
    }

    context(_: Raise<IssueCredentialError>, cfg: CredentialConfiguration)
    suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof?,
        at: Instant,
    ): KeyAttestation? =
        when (val deviceBinding = cfg.deviceBinding) {
            DeviceBinding.None -> {
                notProvided(unvalidatedProof)
                null
            }

            is DeviceBinding.Required -> {
                context(verifyNonce, cfg.reusePolicy, deviceBinding) {
                    required(unvalidatedProof, at)
                }
            }
        }

    context(_: Raise<IssueCredentialError.InvalidProof>)
    private fun notProvided(unvalidatedProof: UnvalidatedProof?) {
        ensure(unvalidatedProof == null) {
            IssueCredentialError.InvalidProof("No proof types supported")
        }
    }

    context(
        _: Raise<IssueCredentialError>,
        deviceBinding: DeviceBinding.Required,
        policy: CredentialReusePolicy,

    )
    private suspend fun required(
        unvalidatedProof: UnvalidatedProof?,
        at: Instant,
    ): KeyAttestation {
        val proofTypesSupported = deviceBinding.proofTypesSupported()
        val proofJwtKwithKA = proofTypesSupported.filterIsInstance<ProofType.Jwt>().firstOrNull()
        val proofAttestation = proofTypesSupported.filterIsInstance<ProofType.Attestation>().firstOrNull()
        val keyAttestation =
            when (unvalidatedProof) {
                null -> {
                    raise(IssueCredentialError.MissingProof)
                }

                is UnvalidatedProof.Jwt if proofJwtKwithKA != null -> {
                    context(proofJwtKwithKA) {
                        validateJwtProofWithKeyAttestation(unvalidatedProof, at)
                    }
                }

                is UnvalidatedProof.Attestation if proofAttestation != null -> {
                    context(proofAttestation) {
                        validateAttestationProof(unvalidatedProof, at)
                    }
                }

                else -> {
                    raise(IssueCredentialError.InvalidProof("Unsupported proof type"))
                }
            }
        return context(verifyNonce) {
            keyAttestation.ensureFreshNonce(at).limitKeys()
        }
    }
}
