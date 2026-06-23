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

import arrow.core.*
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import arrow.core.raise.effect
import arrow.core.raise.fold
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.jose.RequestEncryptionError
import eu.europa.ec.eudi.pidissuer.port.out.jose.RequestEncryptionError.*
import eu.europa.ec.eudi.pidissuer.port.out.jose.decryptCredentialRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import org.slf4j.LoggerFactory
import kotlin.time.Clock

/**
 * Errors that might be raised while trying to issue a credential.
 */
sealed interface IssueCredentialError {
    data class EncryptionError(
        val cause: RequestEncryptionError,
    ) : IssueCredentialError

    data object MissingBothCredentialConfigurationIdAndCredentialIdentifier : IssueCredentialError

    data object BothCredentialConfigurationIdAndCredentialIdentifierProvided : IssueCredentialError

    data class UnsupportedCredentialConfigurationId(
        val credentialConfigurationId: CredentialConfigurationId,
    ) : IssueCredentialError

    data class UnsupportedCredentialType(
        val format: Format,
        val types: List<String> = emptyList(),
    ) : IssueCredentialError

    data class InvalidCredentialIdentifier(
        val credentialIdentifier: CredentialIdentifier,
    ) : IssueCredentialError

    data object MissingProof : IssueCredentialError

    data class InvalidClaims(
        val error: Throwable,
    ) : IssueCredentialError

    data class InvalidProof(
        val msg: String,
        val cause: Throwable? = null,
    ) : IssueCredentialError

    data class InvalidNonce(
        val msg: String,
        val cause: Throwable? = null,
    ) : IssueCredentialError

    data class InvalidEncryptionParameters(
        val msg: String,
        val error: Throwable? = null,
    ) : IssueCredentialError

    data class InvalidClientStatusExpiration(
        val msg: String,
        val cause: Throwable? = null,
    ) : IssueCredentialError

    data class WrongScope(
        val expected: Scope,
    ) : IssueCredentialError

    data object AttestationDatasetNotFound : IssueCredentialError
}

typealias PlainOrEncrypted<T> = Either<T, String>

private val log = LoggerFactory.getLogger(IssueCredential::class.java)

/**
 * Use case for issuing a Credential.
 */
class IssueCredential(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val encryptCredentialResponse: EncryptCredentialResponse,
    private val clock: Clock,
) {
    suspend fun fromEncryptedRequest(
        authorizationContext: AuthorizationContext,
        credentialRequestJwt: String,
    ): IssueCredentialResponse = issueCredential(authorizationContext, credentialRequestJwt.right())

    suspend fun fromPlainRequest(
        authorizationContext: AuthorizationContext,
        credentialRequestTO: CredentialRequestTO,
    ): IssueCredentialResponse = issueCredential(authorizationContext, credentialRequestTO.left())

    private suspend fun issueCredential(
        authorizationContext: AuthorizationContext,
        plainOrEncrypted: PlainOrEncrypted<CredentialRequestTO>,
    ): IssueCredentialResponse =
        effect {
            val request =
                context(credentialIssuerMetadata) {
                    plainOrEncrypted.decryptIfNeeded()
                }
            issueCredential(authorizationContext, request)
        }.fold(
            transform = { it },
            recover = { error ->
                log.warn("Failed to issue credential {}", error)
                error.response()
            },
            catch = { exception ->
                log.error("Unexpected error while issuing credential", exception)
                throw exception
            },
        )

    context(_: Raise<IssueCredentialError>)
    private suspend fun issueCredential(
        authorizationContext: AuthorizationContext,
        request: CredentialRequestTO,
    ): IssueCredentialResponse {
        logRequest(request)
        context(credentialIssuerMetadata, clock) {
            authorizationContext.checkClientStatusExpiration()
        }
        return context(authorizationContext, credentialIssuerMetadata) {
            val validatedRequest = request.validate()
            val (authorizedRequest, issueAttestation) = validatedRequest.authorize()
            val issued = issueAttestation.invoke(authorizedRequest)
            val responseEncryption = authorizedRequest.credentialResponseEncryption
            issued.successResponse(responseEncryption)
        }
    }

    private suspend fun CredentialResponse.successResponse(encryption: RequestedResponseEncryption): IssueCredentialResponse {
        val plain = toVCI()
        return when (encryption) {
            RequestedResponseEncryption.NotRequired -> plain
            is RequestedResponseEncryption.Required -> encryptCredentialResponse(plain, encryption)
        }
    }

    private fun logRequest(credentialRequestTO: CredentialRequestTO) {
        val credentialConfigurationIdOrCredentialIdentifier =
            credentialRequestTO.credentialConfigurationId
                ?: credentialRequestTO.credentialIdentifier
        log.info("Handling issuance request for {}..", credentialConfigurationIdOrCredentialIdentifier)
    }
}

private data class ValidatedRequest(
    val id: Either<CredentialIdentifier, CredentialConfigurationId>,
    val proof: UnvalidatedProof?,
    val credentialResponseEncryption: RequestedResponseEncryption,
)

context(
    _: Raise<IssueCredentialError>,
    metadata: CredentialIssuerMetaData,
)
private suspend fun CredentialRequestTO.validate(): ValidatedRequest {
    val proof = proofs?.toDomain()
    val credentialResponseEncryption =
        credentialResponseEncryption
            ?.toDomain()
            ?: RequestedResponseEncryption.NotRequired

    credentialResponseEncryption.ensureIsSupported(metadata.credentialResponseEncryption)
    return ValidatedRequest(
        id(),
        proof,
        credentialResponseEncryption,
    )
}

context(_: Raise<IssueCredentialError>)
private fun CredentialRequestTO.id(): Either<CredentialIdentifier, CredentialConfigurationId> {
    val credentialConfigurationIdOrCredentialIdentifier =
        Ior.fromNullables(
            credentialIdentifier?.let { CredentialIdentifier(it) },
            credentialConfigurationId?.let { CredentialConfigurationId(it) },
        ) ?: raise(MissingBothCredentialConfigurationIdAndCredentialIdentifier)
    return credentialConfigurationIdOrCredentialIdentifier.fold(
        fa = { credentialId -> credentialId.left() },
        fb = { credentialConfigurationId -> credentialConfigurationId.right() },
        fab = { _, _ -> raise(BothCredentialConfigurationIdAndCredentialIdentifierProvided) },
    )
}

context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext, metadata: CredentialIssuerMetaData)
private fun ValidatedRequest.authorize(): Pair<AuthorizedCredentialRequest, AttestationIssuer> =
    id.fold(
        ifRight = { credentialConfigurationId ->
            val attestationIssuer =
                metadata.attestationIssuers
                    .firstOrNull { iss -> iss.configuration.id == credentialConfigurationId }
            ensureNotNull(attestationIssuer) {
                UnsupportedCredentialConfigurationId(credentialConfigurationId)
            }

            val authorizedScopes = authorizationContext.scopes
            val requiredScopes = attestationIssuer.configuration.scope
            ensure(requiredScopes in authorizedScopes) {
                WrongScope(requiredScopes)
            }

            val authorizedRequest =
                AuthorizedCredentialRequest(
                    proof,
                    credentialResponseEncryption,
                    credentialId = null,
                )
            authorizedRequest to attestationIssuer
        },
        ifLeft = { credentialId ->
            // TODO: check if credential identifier is valid
            //  against the authorization context'
            raise(InvalidCredentialIdentifier(credentialId))
        },
    )

//
// Pre-Processing
//

context(
    _: Raise<EncryptionError>,
    metadata: CredentialIssuerMetaData
)
private suspend fun PlainOrEncrypted<CredentialRequestTO>.decryptIfNeeded(): CredentialRequestTO =
    withError(transform = { EncryptionError(it) }) {
        fun CredentialRequestTO.verifyPlainRequestAgainstEncryptionRequirements() =
            apply {
                ensure(credentialResponseEncryption == null) {
                    ResponseEncryptionRequiresEncryptedRequest
                }
                ensure(metadata.credentialRequestEncryption !is CredentialRequestEncryption.Required) {
                    RequestEncryptionIsRequired
                }
            }
        return fold(
            ifLeft = { plain -> plain.verifyPlainRequestAgainstEncryptionRequirements() },
            ifRight = { encrypted -> decryptCredentialRequest(encrypted) },
        )
    }
//
// Mapping to domain
//

context(_: Raise<IssueCredentialError>)
private fun CredentialRequestTO.ProofsTO.toDomain(): UnvalidatedProof {
    val jwtProofs = jwtProofs?.map { UnvalidatedProof.Jwt(it) }
    val attestations = attestations?.map { UnvalidatedProof.Attestation(it) }
    ensure(1 == listOfNotNull(jwtProofs, attestations).size) {
        InvalidProof("Only a single proof type is allowed")
    }

    val extracted = (jwtProofs.orEmpty() + attestations.orEmpty()).toNonEmptyListOrNull()
    ensureNotNull(extracted) { MissingProof }
    ensure(extracted.size == 1) {
        InvalidProof("You can provide at most 1 proof")
    }
    return extracted.first()
}

/**
 * Gets the [RequestedResponseEncryption] that corresponds to the provided values.
 */
context(_: Raise<InvalidEncryptionParameters>)
private suspend fun CredentialResponseEncryptionTO.toDomain(): RequestedResponseEncryption.Required =
    withContext(Dispatchers.Default) {
        val encryptionKey =
            catch({ JWK.parse(Json.encodeToString(key)) }) {
                raise(InvalidEncryptionParameters("Failed to parse JWK", it))
            }
        val encryptionMethod =
            catch({ EncryptionMethod.parse(method) }) {
                raise(InvalidEncryptionParameters("Failed to parse encryption method", it))
            }
        withError({ InvalidEncryptionParameters(it, null) }) {
            RequestedResponseEncryption
                .Required(
                    encryptionKey,
                    encryptionMethod,
                    zipAlgorithm,
                )
        }
    }

/**
 * Verifies this [RequestedResponseEncryption] is supported by the provided [CredentialResponseEncryption], otherwise
 * raises an [InvalidEncryptionParameters].
 */
context(_: Raise<InvalidEncryptionParameters>)
private fun RequestedResponseEncryption.ensureIsSupported(supported: CredentialResponseEncryption) {
    when (supported) {
        is CredentialResponseEncryption.NotSupported -> {
            ensure(this !is RequestedResponseEncryption.Required) {
                // credential response encryption isn't supported by issuer but required by client
                InvalidEncryptionParameters("credential response encryption is not supported", null)
            }
        }

        is CredentialResponseEncryption.Optional -> {
            if (this is RequestedResponseEncryption.Required) {
                // credential response encryption supported by issuer and required by client
                // ensure provided parameters are supported
                ensure(this.encryptionAlgorithm in supported.parameters.algorithmsSupported) {
                    InvalidEncryptionParameters(
                        "jwe encryption algorithm '${this.encryptionAlgorithm.name}' is not supported",
                    )
                }
                ensure(this.encryptionMethod in supported.parameters.methodsSupported) {
                    InvalidEncryptionParameters(
                        "jwe encryption method '${this.encryptionMethod.name}' is not supported",
                    )
                }
            }
        }

        is CredentialResponseEncryption.Required -> {
            ensure(this is RequestedResponseEncryption.Required) {
                // credential response encryption required by issuer but not required by client
                InvalidEncryptionParameters("credential response encryption is required")
            }

            // ensure provided parameters are supported
            ensure(this.encryptionAlgorithm in supported.parameters.algorithmsSupported) {
                InvalidEncryptionParameters(
                    "jwe encryption algorithm '${this.encryptionAlgorithm.name}' is not supported",
                )
            }
            ensure(this.encryptionMethod in supported.parameters.methodsSupported) {
                InvalidEncryptionParameters(
                    "jwe encryption method '${this.encryptionMethod.name}' is not supported",
                )
            }
        }
    }
}

fun CredentialResponse.toVCI(): IssueCredentialResponse.PlainTO =
    when (this) {
        is CredentialResponse.Issued -> {
            IssueCredentialResponse.PlainTO.issued(
                credentials = JsonArray(credentials),
                notificationId = notificationId?.value,
            )
        }

        is CredentialResponse.Deferred -> {
            IssueCredentialResponse.PlainTO.deferred(transactionId = transactionId.value, interval.inWholeSeconds)
        }
    }

/**
 * Creates a new [IssueCredentialResponse.FailedTO] from the provided [error].
 */
private fun IssueCredentialError.response(): IssueCredentialResponse.FailedTO {
    val (type, description) =
        when (this) {
            is UnsupportedCredentialConfigurationId -> {
                val description = "Unsupported Credential Configuration Id '${credentialConfigurationId.value}'"
                CredentialErrorTypeTo.UNKNOWN_CREDENTIAL_CONFIGURATION to description
            }

            is UnsupportedCredentialType -> {
                CredentialErrorTypeTo.UNKNOWN_CREDENTIAL_CONFIGURATION to "Unsupported format '${format.value}' type `$types`"
            }

            is MissingProof -> {
                CredentialErrorTypeTo.INVALID_PROOF to "The Credential Request must include Proof of Possession"
            }

            is InvalidProof -> {
                CredentialErrorTypeTo.INVALID_PROOF to
                    errorDescriptionWithErrorCauseDescription(msg, cause)
            }

            is InvalidNonce -> {
                CredentialErrorTypeTo.INVALID_NONCE to
                    errorDescriptionWithErrorCauseDescription(msg, cause)
            }

            is InvalidEncryptionParameters -> {
                val description =
                    errorDescriptionWithErrorCauseDescription(
                        "Invalid Credential Response Encryption Parameters: $msg",
                        error,
                    )
                CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS to description
            }

            is WrongScope -> {
                CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Wrong scope. Expected ${expected.value}"
            }

            is InvalidClientStatusExpiration -> {
                CredentialErrorTypeTo.CREDENTIAL_REQUEST_DENIED to
                    errorDescriptionWithErrorCauseDescription("Invalid Client Status: $msg", cause)
            }

            is MissingBothCredentialConfigurationIdAndCredentialIdentifier -> {
                val description = "Either 'format' or 'credential_identifier' must be provided"
                CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
            }

            is BothCredentialConfigurationIdAndCredentialIdentifierProvided -> {
                val description = "Only one of 'format' or 'credential_identifier' must be provided"
                CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
            }

            is InvalidCredentialIdentifier -> {
                val description = "'${credentialIdentifier.value}' is not a valid Credential Identifier"
                CredentialErrorTypeTo.UNKNOWN_CREDENTIAL_IDENTIFIER to description
            }

            is InvalidClaims -> {
                val description =
                    errorDescriptionWithErrorCauseDescription(
                        "'claims' does not have the expected structure",
                        error,
                    )
                CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
            }

            AttestationDatasetNotFound -> {
                val description = "Attestation Dataset not found"
                CredentialErrorTypeTo.ATTESTATION_DATASET_NOT_FOUND to description
            }

            is EncryptionError -> {
                cause.toVCI()
            }
        }
    return IssueCredentialResponse.FailedTO(type, description)
}

private fun RequestEncryptionError.toVCI(): Pair<CredentialErrorTypeTo, String> =
    when (this) {
        is UnparseableEncryptedRequest -> {
            val description =
                errorDescriptionWithErrorCauseDescription("Encrypted request cannot be parsed as a JWT", cause)
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
        }

        is RequestEncryptionIsRequired -> {
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request encryption is required"
        }

        is RequestEncryptionNotSupported -> {
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request encryption is not supported"
        }

        is ResponseEncryptionRequiresEncryptedRequest -> {
            val description = "Credential response encryption requires an encrypted credential request"
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
        }

        is UnsupportedEncryptionAlgorithm -> {
            val description =
                "Unsupported encryption method $encryptionAlgorithm, supported methods: $algorithmsSupported"
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
        }

        is UnsupportedEncryptionMethod -> {
            val description =
                "Unsupported encryption method $encryptionMethod, supported methods: $methodsSupported"
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
        }

        is RequestCompressionNotSupported -> {
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Credential request compression is not supported"
        }

        is UnsupportedRequestCompressionMethod -> {
            val description =
                "Unsupported credential request compression method $compressionAlgorithm, " +
                    "supported methods: $compressionMethodsSupported"
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
        }
    }
