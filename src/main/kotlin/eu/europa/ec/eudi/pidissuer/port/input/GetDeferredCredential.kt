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
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.TransactionId
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptDeferredResponse
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialByTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialResult
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory

@Serializable
data class DeferredCredentialRequestTO(
    @Required @SerialName("transaction_id") val transactionId: String,
)

sealed interface DeferredCredentialSuccessResponse {

    /**
     * Deferred response is plain, no encryption
     */
    @Serializable
    data class PlainTO(
        val credentials: List<CredentialTO>,
        @SerialName("notification_id") val notificationId: String? = null,
    ) : DeferredCredentialSuccessResponse {
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
            ): PlainTO = PlainTO(
                credentials = credentials.map { CredentialTO(it) },
                notificationId = notificationId,
            )
        }

        /**
         * A single issued Credential.
         */
        @Serializable
        @JvmInline
        value class CredentialTO(val value: JsonObject) {
            init {
                val credential = requireNotNull(value["credential"]) {
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
     * Deferred response is encrypted.
     */
    data class EncryptedJwtIssued(
        val jwt: String,
    ) : DeferredCredentialSuccessResponse
}

@Serializable
data class GetDeferredCredentialErrorTO(val error: String) {
    companion object {
        val IssuancePending = GetDeferredCredentialErrorTO("issuance_pending")
        val InvalidTransactionId = GetDeferredCredentialErrorTO("invalid_transaction_id")
    }
}

/**
 * Usecase for retrieving/polling a deferred credential
 */
class GetDeferredCredential(
    val loadDeferredCredentialByTransactionId: LoadDeferredCredentialByTransactionId,
    val encryptCredentialResponse: EncryptDeferredResponse,
) {

    private val log = LoggerFactory.getLogger(GetDeferredCredential::class.java)

    suspend operator fun invoke(
        requestTO: DeferredCredentialRequestTO,
    ): Either<GetDeferredCredentialErrorTO, DeferredCredentialSuccessResponse> = either {
        val transactionId = TransactionId(requestTO.transactionId)
        log.info("GetDeferredCredential for $transactionId ...")
        toTo(loadDeferredCredentialByTransactionId(transactionId))
    }

    private fun Raise<GetDeferredCredentialErrorTO>.toTo(
        loadDeferredCredentialResult: LoadDeferredCredentialResult,
    ): DeferredCredentialSuccessResponse =
        when (loadDeferredCredentialResult) {
            is LoadDeferredCredentialResult.IssuancePending -> raise(GetDeferredCredentialErrorTO.IssuancePending)
            is LoadDeferredCredentialResult.InvalidTransactionId -> raise(GetDeferredCredentialErrorTO.InvalidTransactionId)
            is LoadDeferredCredentialResult.Found -> {
                val plain = DeferredCredentialSuccessResponse.PlainTO(
                    JsonArray(loadDeferredCredentialResult.credential.credentials),
                    loadDeferredCredentialResult.credential.notificationId?.value,
                )

                when (loadDeferredCredentialResult.responseEncryption) {
                    RequestedResponseEncryption.NotRequired -> plain
                    is RequestedResponseEncryption.Required -> encryptCredentialResponse(
                        plain,
                        loadDeferredCredentialResult.responseEncryption,
                    ).getOrThrow()
                }
            }
        }
}
