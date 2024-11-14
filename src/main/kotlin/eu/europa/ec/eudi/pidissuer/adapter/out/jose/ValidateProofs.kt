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

import arrow.core.NonEmptyList
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.domain.isExpired
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.jose.DecryptCNonce
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.time.Clock

/**
 * Validators for Proofs.
 */
internal class ValidateProofs(
    private val validateJwtProof: ValidateJwtProof,
    private val clock: Clock,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
) {

    context(Raise<InvalidProof>)
    suspend operator fun invoke(
        unvalidatedProofs: NonEmptyList<UnvalidatedProof>,
        credentialConfiguration: CredentialConfiguration,
        decryptCNonce: DecryptCNonce?,
    ): NonEmptyList<JWK> = coroutineScope {
        val credentialKeysAndCNonces = unvalidatedProofs.map {
            when (it) {
                is UnvalidatedProof.Jwt -> async { validateJwtProof(it, credentialConfiguration, decryptCNonce) }
                is UnvalidatedProof.LdpVp -> raise(InvalidProof("Supporting only JWT proof"))
            }
        }.awaitAll()

        val cnonces = credentialKeysAndCNonces.map { it.second }.toNonEmptyListOrNull()
        checkNotNull(cnonces)
        ensure(cnonces.distinct().size == 1) {
            InvalidProof("The Proofs of a Credential Request must contain the same CNonce")
        }

        cnonces.head?.let { cnonce ->
            ensure(!cnonce.isExpired(clock.instant())) {
                InvalidProof("CNonce is expired")
            }
        }

        val jwks = credentialKeysAndCNonces.map {
            extractJwkFromCredentialKey(it.first).getOrElse { error ->
                raise(InvalidProof("Unable to extract JWK from CredentialKey", error))
            }
        }.toNonEmptyListOrNull()
        checkNotNull(jwks)
    }
}
