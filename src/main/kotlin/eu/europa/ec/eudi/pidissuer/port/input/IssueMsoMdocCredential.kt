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
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTParser
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueMsoMdocCredentialError.*
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * The format of an MsoMdoc credential request.
 */
internal const val MsoMdocFormat = "mso_mdoc"

private typealias ClaimsTo = Map<String, Map<String, JsonObject>>

/**
 * Transfer object for an MsoMdoc credential request.
 */
@Serializable
private data class MsoMdocCredentialRequestTo(
    @Required val format: String,
    @SerialName("doctype") @Required val docType: String,
    val claims: ClaimsTo? = null,
    val proof: ProofTo? = null,
    @SerialName("credential_encryption_jwk") val credentialResponseEncryptionKey: JsonObject? = null,
    @SerialName("credential_response_encryption_alg") val credentialResponseEncryptionAlgorithm: String? = null,
    @SerialName("credential_response_encryption_enc") val credentialResponseEncryptionMethod: String? = null,
)

/**
 * Errors that can occur while trying to issue an MsoMdoc credential.
 */
sealed interface IssueMsoMdocCredentialError : IssueCredentialError {

    /**
     * Indicates a credential request could not be parsed.
     */
    data class NonParsableCredentialRequest(val error: Throwable) : IssueMsoMdocCredentialError

    /**
     * Indicates a credential request contained an invalid 'format'.
     */
    data class InvalidFormat(val format: String) : IssueMsoMdocCredentialError

    /**
     * Indicates a credential request contained an invalid 'docType'.
     */
    data class InvalidDocType(val docType: String) : IssueMsoMdocCredentialError

    /**
     * Indicates a credential request contained invalid 'claims'.
     */
    data object InvalidClaims : IssueMsoMdocCredentialError

    /**
     * Indicates a credential request contained an invalid 'jwt' proof.
     */
    data class InvalidJwtProof(val error: Throwable) : IssueMsoMdocCredentialError {

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
    data class InvalidCwtProof(val error: Throwable) : IssueMsoMdocCredentialError {

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
     * Indicates a credential request contained an invalid 'credential_encryption_jwk'.
     */
    data class InvalidCredentialResponseEncryptionKey(val error: Throwable) : IssueMsoMdocCredentialError {

        companion object {

            /**
             * Creates a new [InvalidCredentialResponseEncryptionKey] that contains
             * an [IllegalArgumentException] with the provided [error].
             */
            operator fun invoke(error: String): InvalidCredentialResponseEncryptionKey =
                InvalidCredentialResponseEncryptionKey(IllegalArgumentException(error))
        }
    }

    /**
     * Indicates a credential request contained contains an invalid 'credential_response_encryption_alg'.
     */
    data class InvalidCredentialResponseEncryptionAlgorithm(val error: Throwable) : IssueMsoMdocCredentialError {

        companion object {

            /**
             * Creates a new [InvalidCredentialResponseEncryptionAlgorithm] that contains
             * an [IllegalArgumentException] with the provided [error].
             */
            operator fun invoke(error: String): InvalidCredentialResponseEncryptionAlgorithm =
                InvalidCredentialResponseEncryptionAlgorithm(IllegalArgumentException(error))
        }
    }

    /**
     * Indicates a credential request contained contains an invalid 'credential_response_encryption_enc'.
     */
    data class InvalidCredentialResponseEncryptionMethod(val error: Throwable) : IssueMsoMdocCredentialError {
        companion object {

            /**
             * Creates a new [InvalidCredentialResponseEncryptionMethod] that contains
             * an [IllegalArgumentException] with the provided [error].
             */
            operator fun invoke(error: String): InvalidCredentialResponseEncryptionMethod =
                InvalidCredentialResponseEncryptionMethod(IllegalArgumentException(error))
        }
    }
}

/**
 * Raises this [IssueMsoMdocCredentialError] as an error in the context of a [Raise].
 */
context(Raise<IssueMsoMdocCredentialError>)
private fun IssueMsoMdocCredentialError.raise(): Nothing = raise(this)

/**
 * The result of trying to issue an MsoMdoc credential.
 */
internal typealias IssueMsoMdocCredentialResult = Either<IssueMsoMdocCredentialError, String>

/**
 * Service for issuing MsoMdoc credentials.
 */
internal class IssueMsoMdocCredential(private val getPidData: GetPidData) {

    internal suspend operator fun invoke(accessToken: String, request: JsonObject): IssueMsoMdocCredentialResult =
        either {
            val credentialRequestTo = request.toMsoMdocCredentialRequestTo()
            val msoMdocCredentialRequest = credentialRequestTo.getMsoMdocCredentialRequest()
            val proof = credentialRequestTo.getProof()
            val credentialResponseEncryption = credentialRequestTo.getRequestedCredentialResponseEncryption()

            val credentialRequest = CredentialRequest(msoMdocCredentialRequest, proof, credentialResponseEncryption)
            TODO()
        }

    companion object {

        /**
         * Tries to parse a [JsonObject] to a [MsoMdocCredentialRequestTo]. In case of failure
         * an [IssueMsoMdocCredentialError.NonParsableCredentialRequest] error is raised in the current [Raise] context.
         */
        context(Raise<IssueMsoMdocCredentialError>)
        private fun JsonObject.toMsoMdocCredentialRequestTo(): MsoMdocCredentialRequestTo =
            runCatching {
                Json.decodeFromJsonElement<MsoMdocCredentialRequestTo>(this)
            }.getOrElse { NonParsableCredentialRequest(it).raise() }

        /**
         * Gets the [MsoMdocCredentialRequest] that corresponds to this [MsoMdocCredentialRequestTo].
         * In case of an error an [IssueMsoMdocCredentialError] is raised in the current [Raise] context.
         */
        context(Raise<IssueMsoMdocCredentialError>)
        private fun MsoMdocCredentialRequestTo.getMsoMdocCredentialRequest(): MsoMdocCredentialRequest {
            fun MsoMdocCredentialRequestTo.docType(): MsoDocType =
                docType.takeIf { it.isNotBlank() } ?: InvalidDocType(docType).raise()

            fun MsoMdocCredentialRequestTo.claims(): Map<MsoNameSpace, List<MsoMdocAttributeName>> {
                fun String.toMsoNameSpace(): MsoNameSpace = this.takeIf { it.isNotBlank() } ?: InvalidClaims.raise()
                fun Map.Entry<String, JsonObject>.toMsoMdocAttributeName(): MsoMdocAttributeName =
                    this.takeIf { it.key.isNotBlank() && it.value.isEmpty() }?.key ?: InvalidClaims.raise()

                return claims
                    ?.map { namespaceAndAttributes ->
                        val namespace = namespaceAndAttributes.key.toMsoNameSpace()
                        val attributes = namespaceAndAttributes.value.map { it.toMsoMdocAttributeName() }
                        namespace to attributes
                    }
                    ?.toMap()
                    ?: emptyMap()
            }

            return this.takeIf { format == MsoMdocFormat }
                ?.run { MsoMdocCredentialRequest(docType(), claims()) }
                ?: InvalidFormat(format).raise()
        }

        /**
         * Gets the [Proof] that corresponds to this [MsoMdocCredentialRequestTo].
         * In case of an error an [IssueMsoMdocCredentialError] is raised in the current [Raise] context.
         */
        context(Raise<IssueMsoMdocCredentialError>)
        private fun MsoMdocCredentialRequestTo.getProof(): Proof? =
            proof?.run {
                when (proof.type) {
                    ProofTypeTO.JWT -> {
                        ensure(!proof.jwt.isNullOrBlank()) { InvalidJwtProof("'jwt' cannot be null or blank") }
                        ensure(proof.cwt == null) { InvalidJwtProof("'cwt' must be null") }
                        runCatching {
                            val jwt = JWTParser.parse(proof.jwt)
                            Proof.Jwt(jwt)
                        }.getOrElse { InvalidJwtProof(it).raise() }
                    }

                    ProofTypeTO.CWT -> {
                        ensure(proof.jwt == null) { InvalidCwtProof("'jwt' must be null") }
                        ensure(!proof.cwt.isNullOrBlank()) { InvalidCwtProof("'cwt' cannot be null or blank") }
                        Proof.Cwt(proof.cwt)
                    }
                }
            }

        /**
         * Gets the [RequestedCredentialResponseEncryption] that corresponds to this [MsoMdocCredentialRequestTo].
         * In case of an error an [IssueMsoMdocCredentialError] is raised in the current [Raise] context.
         */
        context(Raise<IssueMsoMdocCredentialError>)
        private fun MsoMdocCredentialRequestTo.getRequestedCredentialResponseEncryption(): RequestedCredentialResponseEncryption {
            if (credentialResponseEncryptionKey == null &&
                credentialResponseEncryptionAlgorithm == null &&
                credentialResponseEncryptionMethod == null
            ) {
                return RequestedCredentialResponseEncryption.NotRequired
            }

            val credentialResponseEncryptionKey =
                credentialResponseEncryptionKey
                    ?.let {
                        runCatching {
                            JWK.parse(it)
                        }.getOrElse { InvalidCredentialResponseEncryptionKey(it).raise() }
                    }
                    ?: InvalidCredentialResponseEncryptionKey("missing 'credential_encryption_jwk'").raise()

            val credentialResponseEncryptionAlgorithm =
                credentialResponseEncryptionAlgorithm
                    ?.takeIf { it.isNotBlank() }
                    ?.let { JWEAlgorithm.parse(it) }
                    ?: InvalidCredentialResponseEncryptionAlgorithm("missing 'credential_response_encryption_alg'").raise()

            val credentialResponseEncryptionMethod =
                if (credentialResponseEncryptionMethod == null) {
                    EncryptionMethod.A256GCM
                } else {
                    credentialResponseEncryptionMethod
                        .takeIf { it.isNotBlank() }
                        ?.let { EncryptionMethod.parse(it) }
                        ?: InvalidCredentialResponseEncryptionMethod("missing 'credential_response_encryption_enc'").raise()
                }

            return RequestedCredentialResponseEncryption.Required(
                credentialResponseEncryptionKey,
                credentialResponseEncryptionAlgorithm,
                credentialResponseEncryptionMethod,
            )
        }
    }
}
