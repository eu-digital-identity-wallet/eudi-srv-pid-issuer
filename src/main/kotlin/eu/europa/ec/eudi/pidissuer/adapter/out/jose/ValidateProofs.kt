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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyCNonce
import kotlinx.coroutines.coroutineScope
import java.time.Instant

/**
 * Validators for Proofs.
 */
internal class ValidateProofs(
    private val validateJwtProof: ValidateJwtProof,
    private val verifyCNonce: VerifyCNonce,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
) {

    suspend operator fun invoke(
        unvalidatedProofs: NonEmptyList<UnvalidatedProof>,
        credentialConfiguration: CredentialConfiguration,
        at: Instant,
    ): Either<InvalidProof, NonEmptyList<JWK>> = coroutineScope {
        either {
            val credentialKeysAndCNonces = unvalidatedProofs.map {
                when (it) {
                    is UnvalidatedProof.Jwt ->
                        validateJwtProof(it, credentialConfiguration).bind()
                    is UnvalidatedProof.LdpVp,
                    is UnvalidatedProof.Attestation,
                    -> raise(InvalidProof("Supporting only JWT proof"))
                }
            }

            val cnonces = credentialKeysAndCNonces.map { it.second }.toNonEmptyListOrNull()
            checkNotNull(cnonces)
            ensure(verifyCNonce(cnonces, at)) {
                InvalidProof("CNonce is not valid")
            }

            val jwks = credentialKeysAndCNonces.map {
                extractJwkFromCredentialKey(it.first).getOrElse { error ->
                    raise(InvalidProof("Unable to extract JWK from CredentialKey", error))
                }
            }.toNonEmptyListOrNull()
            checkNotNull(jwks)
        }
    }
}
