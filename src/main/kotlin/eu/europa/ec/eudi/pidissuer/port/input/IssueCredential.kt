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
import eu.europa.ec.eudi.pidissuer.domain.MSO_MDOC_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonObject

@Serializable
enum class FormatTO {
    @SerialName(MSO_MDOC_FORMAT)
    MsoMdoc,
    @SerialName(SD_JWT_VC_FORMAT)
    SdJwtVc,
}

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

interface CredentialResponseEncryptionTO {
    val credentialResponseEncryptionKey: JsonObject?
    val credentialResponseEncryptionAlgorithm: String?
    val credentialResponseEncryptionMethod: String?
}

@Serializable
data class SdJwtVcCredentialDefinition(@Required val type: String, val claims: Map<String, JsonObject>? = null)

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("format")
sealed interface CredentialRequestTO {

    @Required
    val format: FormatTO
    val proof: ProofTo?

    @SerialName("credential_encryption_jwk")
    val credentialResponseEncryptionKey: JsonObject?

    @SerialName("credential_response_encryption_alg")
    val credentialResponseEncryptionAlgorithm: String?

    @SerialName("credential_response_encryption_enc")
    val credentialResponseEncryptionMethod: String?
    val credentialResponseEncryption
        get() = object : CredentialResponseEncryptionTO {
            val self = this@CredentialRequestTO
            override val credentialResponseEncryptionKey = self.credentialResponseEncryptionKey
            override val credentialResponseEncryptionAlgorithm = self.credentialResponseEncryptionAlgorithm
            override val credentialResponseEncryptionMethod = self.credentialResponseEncryptionMethod
        }

    /**
     * Transfer object for an MsoMdoc credential request.
     */
    @Serializable
    @SerialName(MSO_MDOC_FORMAT)
    data class MsoMdoc(
        @SerialName("doctype") @Required val docType: String,
        val claims: Map<String, Map<String, JsonObject>>? = null,
        override val proof: ProofTo? = null,
        @SerialName("credential_encryption_jwk") override val credentialResponseEncryptionKey: JsonObject? = null,
        @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlgorithm: String? = null,
        @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
    ) : CredentialRequestTO {
        override val format: FormatTO = FormatTO.MsoMdoc
    }

    @Serializable
    @SerialName(SD_JWT_VC_FORMAT)
    data class SdJwtVc(
        @Required @SerialName("credential_definition") val credentialDefinition: SdJwtVcCredentialDefinition,
        override val proof: ProofTo? = null,
        @SerialName("credential_encryption_jwk") override val credentialResponseEncryptionKey: JsonObject? = null,
        @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlgorithm: String? = null,
        @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
    ) : CredentialRequestTO {
        override val format: FormatTO = FormatTO.SdJwtVc
    }
}


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

    sealed interface SdJwtVcError : IssueCredentialError {
        /**
         * Indicates a credential request contained an invalid 'docType'.
         */
        data class UnsupportedType(val type: String) : SdJwtVcError
    }
}

class IssueCredential(getPidData: GetPidData) {

    suspend operator fun invoke(
        accessToken: String,
        credentialRequest: CredentialRequestTO
    ): Either<IssueCredentialError, String> =
        either {
            credentialRequest.toDomain().bind()

            TODO()
        }
}


