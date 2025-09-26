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
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import kotlin.time.Instant

internal class ValidateAttestationProof(
    private val verifyKeyAttestation: VerifyKeyAttestation,
) {
    suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Attestation,
        credentialConfiguration: CredentialConfiguration,
        at: Instant,
    ): Either<IssueCredentialError.InvalidProof, Pair<CredentialKey.AttestedKeys, String>> = Either.catch {
        val proofType = credentialConfiguration.proofTypesSupported[ProofTypeEnum.ATTESTATION]
        requireNotNull(proofType) {
            "Credential configuration '${credentialConfiguration.id.value}' doesn't support 'attestation' proofs"
        }
        check(proofType is ProofType.Attestation)
        val keyAttestationJWT = KeyAttestationJWT(unvalidatedProof.jwt)

        require(keyAttestationJWT.jwt.header.algorithm in proofType.signingAlgorithmsSupported) {
            "Key attestation signing algorithm '${keyAttestationJWT.jwt.header.algorithm}' is not supported, " +
                "must be one of: ${proofType.signingAlgorithmsSupported.joinToString(", ") { it.name }}"
        }

        credentialKeyAndNonce(keyAttestationJWT, proofType, at)
    }.mapLeft { IssueCredentialError.InvalidProof("Invalid proof Attestation", it) }

    private suspend fun credentialKeyAndNonce(
        keyAttestationJWT: KeyAttestationJWT,
        proofType: ProofType.Attestation,
        at: Instant,
    ): Pair<CredentialKey.AttestedKeys, String> {
        val (attestedKeys, nonce) = verifyKeyAttestation(
            keyAttestation = keyAttestationJWT,
            signingAlgorithmsSupported = proofType.signingAlgorithmsSupported,
            keyAttestationRequirement = proofType.keyAttestationRequirement,
            expectExpirationClaim = false,
            at = at,
        ).getOrThrow()

        return CredentialKey.AttestedKeys(attestedKeys) to nonce
    }
}
