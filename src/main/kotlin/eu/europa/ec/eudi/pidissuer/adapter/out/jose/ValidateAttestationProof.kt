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
import java.time.Instant

internal class ValidateAttestationProof(
    private val verifyKeyAttestation: VerifyKeyAttestation,
) {
    suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Attestation,
        credentialConfiguration: CredentialConfiguration,
        at: Instant,
    ): Either<IssueCredentialError.InvalidProof, Pair<CredentialKey, String?>> = Either.catch {
        val proofType = credentialConfiguration.proofTypesSupported[ProofTypeEnum.ATTESTATION]
        requireNotNull(proofType) {
            "Credential configuration '${credentialConfiguration.id.value}' doesn't support 'attestation' proofs"
        }
        check(proofType is ProofType.Attestation)
        val keyAttestationJWT = KeyAttestationJWT(unvalidatedProof.jwt)
        val credentialKey = CredentialKey.AttestedKeys.fromKeyAttestation(keyAttestationJWT, proofType, at)
        val nonce = keyAttestationJWT.nonce()

        credentialKey to nonce
    }.mapLeft { IssueCredentialError.InvalidProof("Invalid proof Attestation", it) }

    private suspend fun CredentialKey.AttestedKeys.Companion.fromKeyAttestation(
        keyAttestationJWT: KeyAttestationJWT,
        proofType: ProofType.Attestation,
        at: Instant,
    ): CredentialKey.AttestedKeys {
        val attestedKeys = verifyKeyAttestation(
            keyAttestation = keyAttestationJWT,
            signingAlgorithmsSupported = proofType.signingAlgorithmsSupported,
            keyAttestationRequirement = proofType.keyAttestationRequirement,
            at = at,
        ).getOrThrow()

        return CredentialKey.AttestedKeys(attestedKeys)
    }
}

private fun KeyAttestationJWT.nonce(): String {
    val nonce = jwt.jwtClaimsSet.getStringClaim("nonce")
    requireNotNull(nonce) {
        "Attestation proof must be a key attestation with a nonce set."
    }
    return nonce
}
