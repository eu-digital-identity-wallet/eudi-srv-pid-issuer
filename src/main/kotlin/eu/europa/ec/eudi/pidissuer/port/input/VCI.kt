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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.Either
import com.nimbusds.jwt.EncryptedJWT
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.*
import eu.europa.ec.eudi.pidissuer.port.out.jose.RequestEncryptionError.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class CredentialRequestTO(
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    val proofs: ProofsTO? = null,
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
) {
    @Serializable
    data class ProofsTO(
        @SerialName("jwt") val jwtProofs: List<String>? = null,
        @SerialName("attestation") val attestations: List<String>? = null,
    )
}

@Serializable
data class CredentialResponseEncryptionTO(
    @SerialName("jwk") @Required val key: JsonObject,
    @SerialName("enc") @Required val method: String,
    @SerialName("zip") val zipAlgorithm: String? = null,
)

/**
 * The outcome of trying to issue a Credential.
 */
sealed interface IssueCredentialResponse {
    /**
     * A response to a successfully processed Credential Request.
     * The Credential might have been issued immediately, or its issuance might have been deferred.
     */
    @Serializable
    data class PlainTO(
        val credentials: List<CredentialTO>? = null,
        @SerialName("transaction_id") val transactionId: String? = null,
        @SerialName("interval") val interval: Long? = null,
        @SerialName("notification_id") val notificationId: String? = null,
    ) : IssueCredentialResponse {
        init {
            if (null != transactionId) {
                require(null == credentials) {
                    "cannot provide credentials when transactionId is provided"
                }
                require(null == notificationId) {
                    "cannot provide notificationId when transactionId is provided"
                }
                requireNotNull(interval) {
                    "'interval' must be provided when 'transactionId' is provided"
                }
            } else {
                requireNotNull(!credentials.isNullOrEmpty()) {
                    "'credentials' must be provided"
                }
            }
        }

        companion object {
            /**
             * Multiple credentials have been issued.
             */
            fun issued(
                credentials: List<JsonElement>,
                notificationId: String? = null,
            ): PlainTO = PlainTO(credentials = credentials.map { CredentialTO(it) }, notificationId = notificationId)

            /**
             * Credential issuance has been deferred.
             */
            fun deferred(
                transactionId: String,
                interval: Long,
            ): PlainTO = PlainTO(transactionId = transactionId, interval = interval)
        }

        /**
         * A single-issued Credential.
         */
        @Serializable
        @JvmInline
        value class CredentialTO(
            val value: JsonObject,
        ) {
            init {
                val credential =
                    requireNotNull(value["credential"]) {
                        "value must have a 'credential' property"
                    }

                require(credential is JsonObject || (credential is JsonPrimitive && credential.isString)) {
                    "credential must be either a JsonObjects or a string JsonPrimitive"
                }
            }

            companion object {
                operator fun invoke(
                    credential: JsonElement,
                    builder: JsonObjectBuilder.() -> Unit = { },
                ): CredentialTO =
                    CredentialTO(
                        buildJsonObject {
                            put("credential", credential)
                            builder()
                        },
                    )
            }
        }
    }

    /**
     * A Credential has been issued as an encrypted JWT.
     */
    data class EncryptedJwtIssued(
        val jwt: String,
    ) : IssueCredentialResponse

    /**
     * Indicates a request for issuing a Credential could not be processed due to an error.
     */
    @Serializable
    data class FailedTO(
        @SerialName("error") @Required val type: CredentialErrorTypeTo,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : IssueCredentialResponse
}

/**
 * An error that occurred during the Credential Issuance.
 */
@Serializable
enum class CredentialErrorTypeTo {
    @SerialName("invalid_credential_request")
    INVALID_CREDENTIAL_REQUEST,

    @SerialName("unknown_credential_configuration")
    UNKNOWN_CREDENTIAL_CONFIGURATION,

    @SerialName("unknown_credential_identifier")
    UNKNOWN_CREDENTIAL_IDENTIFIER,

    @SerialName("invalid_proof")
    INVALID_PROOF,

    @SerialName("invalid_nonce")
    INVALID_NONCE,

    @SerialName("invalid_encryption_parameters")
    INVALID_ENCRYPTION_PARAMETERS,

    @SerialName("credential_request_denied")
    CREDENTIAL_REQUEST_DENIED,

    @SerialName("attestation_dataset_not_found")
    ATTESTATION_DATASET_NOT_FOUND,
}

fun errorDescriptionWithErrorCauseDescription(
    description: String,
    cause: Throwable?,
): String =
    buildString {
        append(description)
        if (null != cause && !cause.message.isNullOrBlank()) {
            append(": ${cause.message}")
        }
    }

@Serializable
data class DeferredCredentialRequestTO(
    @Required @SerialName(OpenId4VciSpec.TRANSACTION_ID) val transactionId: String,
    @SerialName(OpenId4VciSpec.CREDENTIAL_RESPONSE_ENCRYPTION)
    val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
)

@Serializable
enum class GetDeferredCredentialErrorTypeTo {
    @SerialName("invalid_transaction_id")
    INVALID_TRANSACTION_ID,

    @SerialName("invalid_encryption_parameters")
    INVALID_ENCRYPTION_PARAMETERS,

    @SerialName("invalid_credential_request")
    INVALID_CREDENTIAL_REQUEST,
}

typealias JsonOrEncryptedJwt<JSON> = Either<JSON, EncryptedJWT>

@Serializable
data class IssuancePendingTO(
    @SerialName(OpenId4VciSpec.TRANSACTION_ID) val transactionId: String,
    @SerialName(OpenId4VciSpec.INTERVAL) val interval: Long,
)

@Serializable
data class IssuedTO(
    val credentials: List<CredentialTO>,
    @SerialName(OpenId4VciSpec.NOTIFICATION_ID) val notificationId: String? = null,
) {
    init {
        require(credentials.isNotEmpty()) {
            "credentials must not be empty"
        }
    }

    companion object {
        /**
         * Multiple credentials have been issued.
         */
        operator fun invoke(
            credentials: JsonArray,
            notificationId: String?,
        ): IssuedTO =
            IssuedTO(
                credentials = credentials.map { CredentialTO(it) },
                notificationId = notificationId,
            )
    }

    /**
     * A single issued Credential.
     */
    @Serializable
    @JvmInline
    value class CredentialTO(
        val value: JsonObject,
    ) {
        init {
            val credential =
                requireNotNull(value["credential"]) {
                    "value must have a 'credential' property"
                }

            require(credential is JsonObject || (credential is JsonPrimitive && credential.isString)) {
                "credential must be either a JsonObjects or a string JsonPrimitive"
            }
        }

        companion object {
            operator fun invoke(
                credential: JsonElement,
                builder: JsonObjectBuilder.() -> Unit = { },
            ): CredentialTO =
                CredentialTO(
                    buildJsonObject {
                        put("credential", credential)
                        builder()
                    },
                )
        }
    }
}

@Serializable
data class FailedTO(
    @SerialName("error") @Required val type: GetDeferredCredentialErrorTypeTo,
    @SerialName("error_description") val errorDescription: String? = null,
)

sealed interface DeferredCredentialResponse {
    data class IssuancePending(
        val content: JsonOrEncryptedJwt<IssuancePendingTO>,
    ) : DeferredCredentialResponse

    data class Issued(
        val content: JsonOrEncryptedJwt<IssuedTO>,
    ) : DeferredCredentialResponse

    data class Failed(
        val content: FailedTO,
    ) : DeferredCredentialResponse
}

/**
 * Response to a Nonce Request.
 */
@Serializable
data class NonceResponseTO(
    @Required @SerialName("c_nonce") val cNonce: String,
)

@Suppress("unused")
@Serializable
enum class EventTypeTO {
    /**
     * The Credential was successfully stored in the Wallet, with or without user action.
     */
    @SerialName("credential_accepted")
    CredentialAccepted,

    /**
     * Unsuccessful Credential issuance was caused by a user action.
     */
    @SerialName("credential_deleted")
    CredentialDeleted,

    /**
     * Unsuccessful Credential issuance (all other cases).
     */
    @SerialName("credential_failure")
    CredentialFailure,
}

@Serializable
data class NotificationRequestTO(
    @SerialName("notification_id") @Required val notificationId: String,
    @SerialName("event") @Required val eventType: EventTypeTO,
    @SerialName("event_description") val description: String? = null,
)

@Serializable
enum class ErrorTypeTO {
    /**
     * The notification_id in the Notification Request was invalid.
     */
    @SerialName("invalid_notification_id")
    InvalidNotificationId,

    /**
     *  The Notification Request is missing a required parameter, includes
     *  an unsupported parameter or parameter value, repeats the same parameter,
     *  or is otherwise malformed.
     */
    @SerialName("invalid_notification_request")
    InvalidNotificationRequest,
}

sealed interface NotificationResponse {
    /**
     * Indicate a Notification Request was successfully handled.
     */
    data object Success : NotificationResponse

    /**
     * Indicates a NotificationRequest could not be successfully handled.
     */
    @Serializable
    data class NotificationErrorResponseTO(
        @SerialName("error") @Required val errorType: ErrorTypeTO,
    ) : NotificationResponse
}

@Serializable
data class AuthorizationCodeTO(
    @SerialName("issuer_state") val issuerState: String? = null,
    @SerialName("authorization_server") val authorizationServer: String? = null,
)

@Suppress("unused")
@Serializable
enum class InputModeTO {
    @SerialName("numeric")
    Numeric,

    @SerialName("text")
    Text,
}

@Serializable
data class TransactionCodeTO(
    @SerialName("input_mode") val inputMode: InputModeTO? = null,
    @SerialName("length") val length: Int? = null,
    @SerialName("description") val description: String? = null,
) {
    init {
        require(length == null || length > 0) {
            "Length if provided should positive number"
        }
        require(description == null || description.length <= 300) {
            "Description is provided should dont exceed 300 characters"
        }
    }
}

@Serializable
data class PreAuthorizedCodeTO(
    @SerialName("pre-authorized_code") @Required val preAuthorizedCode: String,
    @SerialName("tx_code") val transactionCode: TransactionCodeTO? = null,
    @SerialName("interval") val interval: Long? = null,
    @SerialName("authorization_server") val authorizationServer: String? = null,
)

@Serializable
data class GrantsTO(
    @SerialName("authorization_code") val authorizationCode: AuthorizationCodeTO? = null,
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCode: PreAuthorizedCodeTO? = null,
)

/**
 * A Credential Offer as per
 * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1).
 */
@Serializable
data class CredentialsOfferTO(
    @SerialName("credential_issuer") @Required val credentialIssuer: String,
    @SerialName("credential_configuration_ids") @Required val credentialConfigurationIds: Set<String>,
    @SerialName("grants") val grants: GrantsTO? = null,
)
