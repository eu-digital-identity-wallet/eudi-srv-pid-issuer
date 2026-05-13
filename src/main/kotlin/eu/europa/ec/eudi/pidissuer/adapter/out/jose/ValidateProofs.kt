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
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialReusePolicy
import eu.europa.ec.eudi.pidissuer.domain.EudiReusePolicy
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidNonce
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyNonce
import kotlinx.coroutines.coroutineScope
import kotlin.time.Instant

/**
 * Validators for Proofs.
 */
internal class ValidateProofs(
    private val validateJwtProof: ValidateJwtProof,
    private val validateAttestationProof: ValidateAttestationProof,
    private val verifyNonce: VerifyNonce,
) {

    suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof,
        credentialConfiguration: CredentialConfiguration,
        at: Instant,
    ): Either<IssueCredentialError, NonEmptyList<JWK>> = coroutineScope {
        either {
            val credentialKeysAndCNonce =
                when (unvalidatedProof) {
                    is UnvalidatedProof.Jwt ->
                        validateJwtProof(unvalidatedProof, credentialConfiguration, at).bind()
                    is UnvalidatedProof.Attestation ->
                        validateAttestationProof(unvalidatedProof, credentialConfiguration, at).bind()
                }

            val cNonce = credentialKeysAndCNonce.second
            ensure(verifyNonce(cNonce, at)) {
                InvalidNonce("CNonce is not valid")
            }

            val jwks = credentialKeysAndCNonce.first.value.distinct()
                .limitTo(credentialConfiguration.credentialReusePolicy)
                .toNonEmptyListOrNull()

            checkNotNull(jwks)
        }
    }

    private fun List<JWK>.limitTo(policy: CredentialReusePolicy): List<JWK> = when (policy) {
        CredentialReusePolicy.None -> this
        is CredentialReusePolicy.EUDI -> {
            val limit = when {
                policy.options.any { it is EudiReusePolicy.LimitedTime } -> 1
                else -> policy.effectiveBatchSize
            }
            if (limit == null) this else take(limit)
        }
    }
}
