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
import arrow.core.left
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import arrow.core.raise.effect
import arrow.core.raise.getOrElse
import arrow.core.right
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.EncryptedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.decryptCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.*
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptDeferredResponse
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialByTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

@Serializable
sealed interface GetDeferredCredentialError {
    data object InvalidTransactionId : GetDeferredCredentialError

    data class InvalidEncryptionParameters(
        val msg: String,
        val error: Throwable? = null,
    ) : GetDeferredCredentialError
}

private typealias Request = Either<DeferredCredentialRequestTO, String>
private typealias Error = Either<RequestEncryptionError, GetDeferredCredentialError>

private val log = LoggerFactory.getLogger(GetDeferredCredential::class.java)

/**
 * Usecase for retrieving/polling a deferred credential
 */
class GetDeferredCredential(
    val loadDeferredCredentialByTransactionId: LoadDeferredCredentialByTransactionId,
    val encryptCredentialResponse: EncryptDeferredResponse,
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
) {
    suspend fun fromEncryptedRequest(requestJwt: String): DeferredCredentialResponse = getDeferredCredential(requestJwt.right())

    suspend fun fromPlainRequest(requestTO: DeferredCredentialRequestTO): DeferredCredentialResponse =
        getDeferredCredential(requestTO.left())

    private suspend fun getDeferredCredential(encryptedOrPlain: Request): DeferredCredentialResponse =
        effect {
            val request =
                context(credentialIssuerMetadata) {
                    encryptedOrPlain.decryptIfNeeded()
                }
            getDeferredCredential(request)
        }.getOrElse { error ->
            error.response()
        }

    context(_: Raise<Error>)
    private suspend fun getDeferredCredential(request: DeferredCredentialRequestTO): DeferredCredentialResponse =
        withError(transform = { it.right() }) {
            val transactionId = TransactionId(request.transactionId)
            val credentialResponseEncryption =
                request.credentialResponseEncryption
                    ?.let { toDomain(it) }
                    ?: RequestedResponseEncryption.NotRequired
            log.info("GetDeferredCredential for $transactionId ...")

            return when (val result = loadDeferredCredentialByTransactionId(transactionId)) {
                LoadDeferredCredentialResult.InvalidTransactionId -> {
                    raise(GetDeferredCredentialError.InvalidTransactionId)
                }

                is LoadDeferredCredentialResult.IssuancePending -> {
                    context(encryptCredentialResponse) {
                        result.response(credentialResponseEncryption)
                    }
                }

                is LoadDeferredCredentialResult.Found -> {
                    context(encryptCredentialResponse) {
                        result.response(credentialResponseEncryption)
                    }
                }
            }
        }
}

//
// Request pre-processing
//

context(_: Raise<Error>, credentialIssuerMetadata: CredentialIssuerMetaData)
private suspend fun Request.decryptIfNeeded(): DeferredCredentialRequestTO =
    withError(transform = { it.left() }) {
        fun DeferredCredentialRequestTO.verifyEncryptionForPlainRequest() {
            ensure(credentialResponseEncryption == null) {
                ResponseEncryptionRequiresEncryptedRequest
            }
            ensure(credentialIssuerMetadata.credentialRequestEncryption !is CredentialRequestEncryption.Required) {
                RequestEncryptionIsRequired
            }
        }

        suspend fun String.decrypt(): DeferredCredentialRequestTO = decryptCredentialRequest(this)

        return fold(
            { plain -> plain.apply { verifyEncryptionForPlainRequest() } },
            { jwt -> jwt.decrypt() },
        )
    }

context(_: Raise<GetDeferredCredentialError>)
private suspend fun toDomain(requestTO: CredentialResponseEncryptionTO): RequestedResponseEncryption.Required =
    withContext(Dispatchers.Default) {
        val encryptionKey =
            catch({ JWK.parse(Json.encodeToString(requestTO.key)) }) {
                raise(GetDeferredCredentialError.InvalidEncryptionParameters("Failed to parse JWK", it))
            }
        val encryptionMethod =
            catch({ EncryptionMethod.parse(requestTO.method) }) {
                raise(
                    GetDeferredCredentialError.InvalidEncryptionParameters(
                        "Failed to parse encryption method",
                        it,
                    ),
                )
            }
        withError({ GetDeferredCredentialError.InvalidEncryptionParameters(it) }) {
            RequestedResponseEncryption
                .Required(
                    encryptionKey,
                    encryptionMethod,
                    requestTO.zipAlgorithm,
                )
        }
    }

//
// Respons
//
context(encryptCredentialResponse: EncryptDeferredResponse)
private suspend fun LoadDeferredCredentialResult.IssuancePending.response(
    credentialResponseEncryption: RequestedResponseEncryption,
): DeferredCredentialResponse.IssuancePending {
    val plain =
        IssuancePendingTO(
            transactionId = deferred.transactionId.value,
            interval = deferred.interval.inWholeSeconds,
        )

    return when (credentialResponseEncryption) {
        RequestedResponseEncryption.NotRequired -> {
            DeferredCredentialResponse.IssuancePending(plain.left())
        }

        is RequestedResponseEncryption.Required -> {
            val jwt =
                encryptCredentialResponse(
                    plain,
                    credentialResponseEncryption,
                )
            DeferredCredentialResponse.IssuancePending(jwt.right())
        }
    }
}

context(encryptCredentialResponse: EncryptDeferredResponse)
private suspend fun LoadDeferredCredentialResult.Found.response(
    credentialResponseEncryption: RequestedResponseEncryption,
): DeferredCredentialResponse.Issued {
    val plain =
        IssuedTO(
            credentials = JsonArray(credential.credentials),
            notificationId = credential.notificationId?.value,
        )

    return when (credentialResponseEncryption) {
        RequestedResponseEncryption.NotRequired -> {
            DeferredCredentialResponse.Issued(plain.left())
        }

        is RequestedResponseEncryption.Required -> {
            val jwt =
                encryptCredentialResponse(
                    plain,
                    credentialResponseEncryption,
                )
            DeferredCredentialResponse.Issued(jwt.right())
        }
    }
}

//
// Error Response
//

private fun Error.response(): DeferredCredentialResponse =
    fold(
        ifLeft = { encryptionError -> encryptionError.toTO() },
        ifRight = { issuanceError -> issuanceError.toTO() },
    )

private fun RequestEncryptionError.toTO(): DeferredCredentialResponse.Failed {
    val (type, description) =
        when (this) {
            is UnparseableEncryptedRequest -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                    errorDescriptionWithErrorCauseDescription("Encrypted request cannot be parsed as a JWT", cause)
            }

            is RequestEncryptionIsRequired -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request encryption is required"
            }

            is RequestEncryptionNotSupported -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request encryption is not supported"
            }

            is ResponseEncryptionRequiresEncryptedRequest -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                    "Credential response encryption requires an encrypted credential request"
            }

            is UnsupportedEncryptionAlgorithm -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                    "Unsupported encryption method $encryptionAlgorithm, supported methods: $algorithmsSupported"
            }

            is UnsupportedEncryptionMethod -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                    "Unsupported encryption method $encryptionMethod, supported methods: $methodsSupported"
            }

            is RequestCompressionNotSupported -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request compression is not supported"
            }

            is UnsupportedRequestCompressionMethod -> {
                GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                    "Unsupported credential request compression method $compressionAlgorithm, " +
                    "supported methods: $compressionMethodsSupported"
            }
        }
    return DeferredCredentialResponse.Failed(FailedTO(type, description))
}

private fun GetDeferredCredentialError.toTO(): DeferredCredentialResponse.Failed {
    val (type, description) =
        when (this) {
            is GetDeferredCredentialError.InvalidTransactionId -> {
                GetDeferredCredentialErrorTypeTo.INVALID_TRANSACTION_ID to null
            }

            is GetDeferredCredentialError.InvalidEncryptionParameters -> {
                GetDeferredCredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS to
                    errorDescriptionWithErrorCauseDescription("Invalid encryption parameters", error)
            }
        }
    return DeferredCredentialResponse.Failed(FailedTO(type, description))
}
