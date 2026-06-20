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

import arrow.core.left
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import arrow.core.raise.effect
import arrow.core.raise.fold
import arrow.core.right
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequestEncryption
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.TransactionId
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptDeferredResponse
import eu.europa.ec.eudi.pidissuer.port.out.jose.RequestEncryptionError
import eu.europa.ec.eudi.pidissuer.port.out.jose.RequestEncryptionError.*
import eu.europa.ec.eudi.pidissuer.port.out.jose.decryptCredentialRequest
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialByTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import org.slf4j.LoggerFactory

sealed interface GetDeferredCredentialError {
    data class EncryptionError(
        val cause: RequestEncryptionError,
    ) : GetDeferredCredentialError

    data object InvalidTransactionId : GetDeferredCredentialError

    data class InvalidEncryptionParameters(
        val msg: String,
        val error: Throwable? = null,
    ) : GetDeferredCredentialError
}

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

    private suspend fun getDeferredCredential(encryptedOrPlain: PlainOrEncrypted<DeferredCredentialRequestTO>): DeferredCredentialResponse =
        effect {
            val request =
                context(credentialIssuerMetadata) {
                    encryptedOrPlain.decryptIfNeeded()
                }
            doGetDeferredCredential(request)
        }.fold(
            transform = { it },
            recover = { error ->
                log.warn("Failed to get deferred credential {}", error)
                error.response()
            },
            catch = { exception ->
                log.error("Unexpected error while getting deferred credential", exception)
                throw exception
            },
        )

    context(_: Raise<GetDeferredCredentialError>)
    private suspend fun doGetDeferredCredential(request: DeferredCredentialRequestTO): DeferredCredentialResponse {
        val transactionId = TransactionId(request.transactionId)
        val credentialResponseEncryption =
            request.credentialResponseEncryption
                ?.let { toRequestedResponseEncryption(it) }
                ?: RequestedResponseEncryption.NotRequired
        log.info("GetDeferredCredential for {} ...", transactionId)

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

context(_: Raise<GetDeferredCredentialError>, credentialIssuerMetadata: CredentialIssuerMetaData)
private suspend fun PlainOrEncrypted<DeferredCredentialRequestTO>.decryptIfNeeded(): DeferredCredentialRequestTO =
    withError(transform = { GetDeferredCredentialError.EncryptionError(it) }) {
        fun DeferredCredentialRequestTO.verifyEncryptionForPlainRequest() {
            ensure(credentialResponseEncryption == null) {
                ResponseEncryptionRequiresEncryptedRequest
            }
            ensure(credentialIssuerMetadata.credentialRequestEncryption !is CredentialRequestEncryption.Required) {
                RequestEncryptionIsRequired
            }
        }

        return fold(
            { plain -> plain.apply { verifyEncryptionForPlainRequest() } },
            { encrypted -> decryptCredentialRequest(encrypted) },
        )
    }

context(_: Raise<GetDeferredCredentialError>)
private suspend fun toRequestedResponseEncryption(requestTO: CredentialResponseEncryptionTO): RequestedResponseEncryption.Required =
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

private fun GetDeferredCredentialError.response(): DeferredCredentialResponse.Failed {
    val (type, description) =
        when (this) {
            is GetDeferredCredentialError.InvalidTransactionId -> {
                GetDeferredCredentialErrorTypeTo.INVALID_TRANSACTION_ID to null
            }

            is GetDeferredCredentialError.InvalidEncryptionParameters -> {
                GetDeferredCredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS to
                    errorDescriptionWithErrorCauseDescription("Invalid encryption parameters", error)
            }

            is GetDeferredCredentialError.EncryptionError -> {
                cause.toVCI()
            }
        }
    return DeferredCredentialResponse.Failed(FailedTO(type, description))
}

private fun RequestEncryptionError.toVCI(): Pair<GetDeferredCredentialErrorTypeTo, String> =
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
