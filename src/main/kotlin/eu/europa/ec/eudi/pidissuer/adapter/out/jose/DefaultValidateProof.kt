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
    private val validateJwtProof: ValidateJwtProof,
    private val validateAttestationProof: ValidateAttestationProof,
    private val verifyNonce: VerifyNonce,
) : ValidateProof {
    context(_: Raise<IssueCredentialError>, _: CredentialConfiguration,)
    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof,
        at: Instant,
    ): ValidatedProof {
        val validatedProof = validate(unvalidatedProof, at)
        val limitedCredentialKeys = validatedProof.credentialKeys.limitToPolicy()
        return validatedProof.copy(credentialKeys = limitedCredentialKeys)
    }

    context(_: Raise<IssueCredentialError>, credentialConfiguration: CredentialConfiguration,)
    private suspend fun validate(
        unvalidatedProof: UnvalidatedProof,
        at: Instant,
    ): ValidatedProof {
        val proof =
            when (unvalidatedProof) {
                is UnvalidatedProof.Jwt -> {
                    validateJwtProof(unvalidatedProof, at)
                }

                is UnvalidatedProof.Attestation -> {
                    validateAttestationProof(unvalidatedProof, at)
                }
            }
        ensure(verifyNonce(proof.cNonce, at)) {
            InvalidNonce("CNonce is not valid")
        }
        return proof
    }
}

context(credentialConfiguration: CredentialConfiguration)
private fun CredentialKeys.limitToPolicy(): CredentialKeys =
    when (val policy = credentialConfiguration.credentialReusePolicy) {
        CredentialReusePolicy.None -> {
            this
        }

        is CredentialReusePolicy.EUDI -> {
            val limit =
                when {
                    policy.options.any { it is EudiReusePolicy.LimitedTime } -> 1
                    else -> policy.effectiveBatchSize
                }
            if (limit == null) this else CredentialKeys(value.take(limit).toNonEmptyListOrThrow())
        }
    }
