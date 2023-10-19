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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.Either
import arrow.core.raise.either
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
enum class ProofTypeTO {
    @SerialName("jwt")
    JWT,

    @SerialName("cwt")
    CWT,
}

@Serializable
data class ProofTo(
    @SerialName("proof_type") @Required val type: ProofTypeTO,
    val jwt: String? = null,
    val cwt: String? = null,
)

/**
 * Errors that might be raised while trying to issue a credential.
 */
sealed interface IssueCredentialError {

    /**
     * Indicates a credential request contained an invalid 'format'.
     */
    data class InvalidFormat(val format: String?) : IssueCredentialError

    /**
     * Indicates a credential request could not be parsed.
     */
    data class NonParsableCredentialRequest(val error: Throwable) : IssueCredentialError

    /**
     * Indicates a credential request contained invalid 'claims'.
     */
    data object InvalidClaims : IssueCredentialError

    /**
     * Indicates a credential request contained an invalid 'jwt' proof.
     */
    data class InvalidJwtProof(val error: Throwable) : IssueCredentialError {

        companion object {

            /**
             * Creates a new [InvalidJwtProof] that contains
             * an [IllegalArgumentException] with the provided [error].
             */
            operator fun invoke(error: String): InvalidJwtProof =
                InvalidJwtProof(IllegalArgumentException(error))
        }
    }

    /**
     * Indicates a credential request contained an invalid 'cwt' proof.
     */
    data class InvalidCwtProof(val error: Throwable) : IssueCredentialError {

        companion object {

            /**
             * Creates a new [InvalidCwtProof] that contains
             * an [IllegalArgumentException] with the provided [error].
             */
            operator fun invoke(error: String): InvalidCwtProof =
                InvalidCwtProof(IllegalArgumentException(error))
        }
    }

    /**
     * Indicates a credential request contained contains an invalid 'credential_response_encryption_alg'.
     */
    data class InvalidCredentialResponseEncryption(val error: Throwable) : IssueCredentialError

    /**
     * Errors that can occur while trying to issue an MsoMdoc credential.
     */
    sealed interface IssueMsoMdocCredentialError : IssueCredentialError {

        /**
         * Indicates a credential request contained an invalid 'docType'.
         */
        data class InvalidDocType(val docType: String) : IssueMsoMdocCredentialError
    }
}

class IssueCredential(getPidData: GetPidData) {

    suspend operator fun invoke(accessToken: String, request: JsonObject): Either<IssueCredentialError, String> =
        either {
            val credentialRequest = parseCredentialRequest(request).bind()

            TODO()
        }
}
