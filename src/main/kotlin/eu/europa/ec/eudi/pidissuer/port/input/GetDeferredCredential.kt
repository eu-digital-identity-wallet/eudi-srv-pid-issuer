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
import arrow.core.getOrElse
import arrow.core.left
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.right
import com.nimbusds.jwt.EncryptedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.decryptCredentialRequest
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequestEncryption
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.TransactionId
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.RequestCompressionNotSupported
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.RequestEncryptionIsRequired
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.RequestEncryptionNotSupported
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.ResponseEncryptionRequiresEncryptedRequest
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.UnparseableEncryptedRequest
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.UnsupportedEncryptionAlgorithm
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.UnsupportedEncryptionMethod
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.UnsupportedRequestCompressionMethod
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
        ): IssuedTO = IssuedTO(
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

@Serializable
data class FailedTO(
    @SerialName("error") @Required val type: GetDeferredCredentialErrorTypeTo,
    @SerialName("error_description") val errorDescription: String? = null,
)

sealed interface DeferredCredentialResponse {
    data class IssuancePending(val content: JsonOrEncryptedJwt<IssuancePendingTO>) : DeferredCredentialResponse
    data class Issued(val content: JsonOrEncryptedJwt<IssuedTO>) : DeferredCredentialResponse
    data class Failed(val content: FailedTO) : DeferredCredentialResponse
}

@Serializable
sealed interface GetDeferredCredentialError {
    data object InvalidTransactionId : GetDeferredCredentialError

    data class InvalidEncryptionParameters(val error: Throwable) : GetDeferredCredentialError
}

private fun GetDeferredCredentialError.toTO(): DeferredCredentialResponse.Failed {
    val (type, description) = when (this) {
        is GetDeferredCredentialError.InvalidTransactionId ->
            GetDeferredCredentialErrorTypeTo.INVALID_TRANSACTION_ID to null

        is GetDeferredCredentialError.InvalidEncryptionParameters ->
            GetDeferredCredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS to
                errorDescriptionWithErrorCauseDescription("Invalid encryption parameters", error)
    }
    return DeferredCredentialResponse.Failed(FailedTO(type, description))
}

/**
 * Usecase for retrieving/polling a deferred credential
 */
class GetDeferredCredential(
    val loadDeferredCredentialByTransactionId: LoadDeferredCredentialByTransactionId,
    val encryptCredentialResponse: EncryptDeferredResponse,
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
) {

    private val log = LoggerFactory.getLogger(GetDeferredCredential::class.java)

    suspend fun fromEncryptedRequest(
        requestJwt: String,
    ): DeferredCredentialResponse = either {
        val requestTO: DeferredCredentialRequestTO = decryptCredentialRequest(requestJwt, credentialIssuerMetadata)
        invoke(requestTO)
    }.getOrElse { error ->
        error.toTO()
    }

    suspend fun fromPlainRequest(
        requestTO: DeferredCredentialRequestTO,
    ): DeferredCredentialResponse = either {
        ensure(requestTO.credentialResponseEncryption == null) {
            ResponseEncryptionRequiresEncryptedRequest
        }
        ensure(credentialIssuerMetadata.credentialRequestEncryption !is CredentialRequestEncryption.Required) {
            RequestEncryptionIsRequired
        }
        invoke(requestTO)
    }.getOrElse { error ->
        error.toTO()
    }

    private suspend operator fun invoke(
        requestTO: DeferredCredentialRequestTO,
    ): DeferredCredentialResponse = either {
        val transactionId = TransactionId(requestTO.transactionId)
        log.info("GetDeferredCredential for $transactionId ...")
        val loadDeferredCredentialResult = loadDeferredCredentialByTransactionId(transactionId)
        val credentialResponseEncryption = requestTO.credentialResponseEncryption?.let { toDomain(it) }
            ?: RequestedResponseEncryption.NotRequired
        toTo(loadDeferredCredentialResult, credentialResponseEncryption)
    }.getOrElse { error ->
        error.toTO()
    }

    fun Raise<GetDeferredCredentialError>.toDomain(requestTO: CredentialResponseEncryptionTO) =
        RequestedResponseEncryption.Required(
            Json.encodeToString(requestTO.key),
            requestTO.method,
            requestTO.zipAlgorithm,
        ).getOrElse { raise(GetDeferredCredentialError.InvalidEncryptionParameters(it)) }

    private fun Raise<GetDeferredCredentialError>.toTo(
        loadDeferredCredentialResult: LoadDeferredCredentialResult,
        credentialResponseEncryption: RequestedResponseEncryption,
    ): DeferredCredentialResponse =
        when (loadDeferredCredentialResult) {
            is LoadDeferredCredentialResult.InvalidTransactionId -> raise(GetDeferredCredentialError.InvalidTransactionId)
            is LoadDeferredCredentialResult.IssuancePending -> {
                val plain = IssuancePendingTO(
                    loadDeferredCredentialResult.deferred.transactionId.value,
                    loadDeferredCredentialResult.deferred.interval.inWholeSeconds,
                )

                when (credentialResponseEncryption) {
                    RequestedResponseEncryption.NotRequired -> DeferredCredentialResponse.IssuancePending(plain.left())
                    is RequestedResponseEncryption.Required -> {
                        val jwt = encryptCredentialResponse(
                            plain,
                            credentialResponseEncryption,
                        ).getOrThrow()
                        DeferredCredentialResponse.IssuancePending(jwt.right())
                    }
                }
            }
            is LoadDeferredCredentialResult.Found -> {
                val plain = IssuedTO(
                    JsonArray(loadDeferredCredentialResult.credential.credentials),
                    loadDeferredCredentialResult.credential.notificationId?.value,
                )

                when (credentialResponseEncryption) {
                    RequestedResponseEncryption.NotRequired -> DeferredCredentialResponse.Issued(plain.left())
                    is RequestedResponseEncryption.Required -> {
                        val jwt = encryptCredentialResponse(
                            plain,
                            credentialResponseEncryption,
                        ).getOrThrow()
                        DeferredCredentialResponse.Issued(jwt.right())
                    }
                }
            }
        }
}
private fun RequestEncryptionError.toTO(): DeferredCredentialResponse.Failed {
    val (type, description) = when (this) {
        is UnparseableEncryptedRequest ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                errorDescriptionWithErrorCauseDescription("Encrypted request cannot be parsed as a JWT", cause)

        is RequestEncryptionIsRequired ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request encryption is required"

        is RequestEncryptionNotSupported ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request encryption is not supported"

        is ResponseEncryptionRequiresEncryptedRequest ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                "Credential response encryption requires an encrypted credential request"

        is UnsupportedEncryptionAlgorithm ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                "Unsupported encryption method $encryptionAlgorithm, supported methods: $algorithmsSupported"

        is UnsupportedEncryptionMethod ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                "Unsupported encryption method $encryptionMethod, supported methods: $methodsSupported"

        is RequestCompressionNotSupported ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request compression is not supported"

        is UnsupportedRequestCompressionMethod ->
            GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                "Unsupported credential request compression method $compressionAlgorithm, " +
                "supported methods: $compressionMethodsSupported"
    }
    return DeferredCredentialResponse.Failed(FailedTO(type, description))
}
