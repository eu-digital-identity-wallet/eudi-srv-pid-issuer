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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
        val credential: JsonElement?,
        val credentials: JsonArray?,
        @SerialName("notification_id") val notificationId: String? = null,
    ) : DeferredCredentialSuccessResponse {
        init {
            require((credential != null) xor (credentials != null)) {
                "exactly one of 'credential' or 'credentials' must be provided"
            }
            credential?.also { credential ->
                require(credential is JsonObject || (credential is JsonPrimitive && credential.isString)) {
                    "credential must either be a JsonObject or a string JsonPrimitive"
                }
            }
            credentials?.forEach { credential ->
                require(credential is JsonObject || (credential is JsonPrimitive && credential.isString)) {
                    "credentials must contain either JsonObjects or string JsonPrimitives"
                }
            }
        }

        companion object {
            /**
             * Single credential has been issued.
             */
            fun single(
                credential: JsonElement,
                notificationId: String?,
            ): PlainTO = PlainTO(
                credential = credential,
                credentials = null,
                notificationId = notificationId,
            )

            /**
             * Multiple credentials have been issued.
             */
            fun multiple(
                credentials: JsonArray,
                notificationId: String?,
            ): PlainTO = PlainTO(
                credential = null,
                credentials = credentials,
                notificationId = notificationId,
            )
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
                val plain = when (loadDeferredCredentialResult.credential.credentials.size) {
                    1 -> DeferredCredentialSuccessResponse.PlainTO.single(
                        loadDeferredCredentialResult.credential.credentials.head,
                        loadDeferredCredentialResult.credential.notificationId?.value,
                    )

                    else -> DeferredCredentialSuccessResponse.PlainTO.multiple(
                        JsonArray(loadDeferredCredentialResult.credential.credentials),
                        loadDeferredCredentialResult.credential.notificationId?.value,
                    )
                }

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
