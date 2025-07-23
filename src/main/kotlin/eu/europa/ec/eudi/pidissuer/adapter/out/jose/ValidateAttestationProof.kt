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
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError

internal class ValidateAttestationProof {

    operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Attestation,
        credentialConfiguration: CredentialConfiguration,
    ): Either<IssueCredentialError.InvalidProof, Pair<CredentialKey, String?>> = Either.catch {
        val proofType = credentialConfiguration.proofTypesSupported[ProofTypeEnum.ATTESTATION]
        requireNotNull(proofType) {
            "Credential configuration '${credentialConfiguration.id.value}' doesn't support 'attestation' proofs"
        }
        check(proofType is ProofType.Attestation)

        val signedJWT = SignedJWT.parse(unvalidatedProof.jwt)
        // TODO: Validate signature

        val keyAttestationJWT = KeyAttestationJWT(signedJWT).also {
            it.ensureValidKeyAttestation(proofType.keyAttestationRequirement)
        }
        val attestedKeys = CredentialKey.AttestedKeys(keyAttestationJWT.attestedKeys)

        val nonce = signedJWT.jwtClaimsSet.getStringClaim("nonce")
        requireNotNull(nonce) {
            "Attestation proof must be a key attestation with a nonce set."
        }
        attestedKeys to nonce
    }.mapLeft { IssueCredentialError.InvalidProof("Invalid proof Attestation", it) }
}
