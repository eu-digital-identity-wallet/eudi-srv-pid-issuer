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
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrThrow
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidNonce
import eu.europa.ec.eudi.pidissuer.port.out.credential.ValidateCredentialProof
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyNonce
import kotlinx.coroutines.coroutineScope
import kotlin.time.Instant

/**
 * Validators for Proofs.
 */
internal class ValidateProof(
    private val validateJwtProof: ValidateJwtProof,
    private val validateAttestationProof: ValidateAttestationProof,
    private val verifyNonce: VerifyNonce,
) : ValidateCredentialProof {

    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof,
        credentialConfiguration: CredentialConfiguration,
        at: Instant,
    ): Either<IssueCredentialError, ValidatedProof> = coroutineScope {
        either {
            val validatedProof =
                when (unvalidatedProof) {
                    is UnvalidatedProof.Jwt ->
                        validateJwtProof(unvalidatedProof, credentialConfiguration, at).bind()
                    is UnvalidatedProof.Attestation ->
                        validateAttestationProof(unvalidatedProof, credentialConfiguration, at).bind()
                }

            ensure(verifyNonce(validatedProof.cNonce, at)) {
                InvalidNonce("CNonce is not valid")
            }

            val limitedCredentialKeys = validatedProof.credentialKeys
                .limitTo(credentialConfiguration.credentialReusePolicy)

            validatedProof.copy(credentialKeys = limitedCredentialKeys)
        }
    }

    private fun CredentialKeys.limitTo(policy: CredentialReusePolicy): CredentialKeys = when (policy) {
        CredentialReusePolicy.None -> this
        is CredentialReusePolicy.EUDI -> {
            val limit = when {
                policy.options.any { it is EudiReusePolicy.LimitedTime } -> 1
                else -> policy.effectiveBatchSize
            }
            if (limit == null) this else CredentialKeys(value.take(limit).toNonEmptyListOrThrow())
        }
    }
}
