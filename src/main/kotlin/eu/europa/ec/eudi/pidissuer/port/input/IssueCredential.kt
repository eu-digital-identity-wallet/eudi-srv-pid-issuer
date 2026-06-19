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
import arrow.core.raise.*
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.decryptCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.*
import eu.europa.ec.eudi.pidissuer.port.input.RequestEncryptionError.*
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.credential.ResolveCredentialRequestByCredentialIdentifier
import eu.europa.ec.eudi.pidissuer.port.out.credential.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import kotlin.time.Clock

@Serializable
data class ProofsTO(
    @SerialName("jwt") val jwtProofs: List<String>? = null,
    @SerialName("attestation") val attestations: List<String>? = null,
)

@Serializable
data class CredentialResponseEncryptionTO(
    @SerialName("jwk") @Required val key: JsonObject,
    @SerialName("enc") @Required val method: String,
    @SerialName("zip") val zipAlgorithm: String? = null,
)

@Serializable
data class CredentialRequestTO(
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    val proofs: ProofsTO? = null,
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
)

/**
 * Errors that might be raised while trying to issue a credential.
 */
sealed interface IssueCredentialError {
    /**
     * Indicates that both 'credential_configuration_id' and 'credential_identifier' was missing from a Credential Request.
     */
    data object MissingBothCredentialConfigurationIdAndCredentialIdentifier : IssueCredentialError

    /**
     * Indicates that a Credential Request erroneously contained both 'credential_configuration_id' and 'credential_identifier'.
     */
    data object BothCredentialConfigurationIdAndCredentialIdentifierProvided : IssueCredentialError

    /**
     * Indicates a credential request contained an unsupported 'format'.
     */
    data class UnsupportedCredentialConfigurationId(
        val credentialConfigurationId: CredentialConfigurationId,
    ) : IssueCredentialError

    data class UnsupportedCredentialType(
        val format: Format,
        val types: List<String> = emptyList(),
    ) : IssueCredentialError

    /**
     * Indicates that a Credential Request contained an invalid 'credential_identifier'.
     */
    data class InvalidCredentialIdentifier(
        val credentialIdentifier: CredentialIdentifier,
    ) : IssueCredentialError

    /**
     * Indicates that Proof of Possession was not provided.
     */
    data object MissingProof : IssueCredentialError

    /**
     * Indicates the provided 'claims' did not have the expected structure.
     */
    data class InvalidClaims(
        val error: Throwable,
    ) : IssueCredentialError

    /**
     * Indicates a credential request contained an invalid 'jwt' proof.
     */
    data class InvalidProof(
        val msg: String,
        val cause: Throwable? = null,
    ) : IssueCredentialError

    /**
     * Indicates a credential request contained a proof with an invalid 'nonce'.
     */
    data class InvalidNonce(
        val msg: String,
        val cause: Throwable? = null,
    ) : IssueCredentialError

    /**
     * Indicates a credential request contains an invalid 'credential_response_encryption_alg'.
     */
    data class InvalidEncryptionParameters(
        val msg: String,
        val error: Throwable? = null,
    ) : IssueCredentialError

    /**
     * Indicates a 'client_status` error'.
     */
    data class InvalidClientStatus(
        val msg: String,
        val cause: Throwable? = null,
    ) : IssueCredentialError

    data class WrongScope(
        val expected: Scope,
    ) : IssueCredentialError

    data object AttestationDatasetNotFound : IssueCredentialError
}

sealed interface RequestEncryptionError {
    data class UnparseableEncryptedRequest(
        val cause: Throwable? = null,
    ) : RequestEncryptionError

    data object RequestEncryptionNotSupported : RequestEncryptionError

    data object RequestEncryptionIsRequired : RequestEncryptionError

    data object ResponseEncryptionRequiresEncryptedRequest : RequestEncryptionError

    data class UnsupportedEncryptionAlgorithm(
        val encryptionAlgorithm: JWEAlgorithm,
        val algorithmsSupported: NonEmptySet<JWEAlgorithm>,
    ) : RequestEncryptionError

    data class UnsupportedEncryptionMethod(
        val encryptionMethod: EncryptionMethod,
        val methodsSupported: NonEmptySet<EncryptionMethod>,
    ) : RequestEncryptionError

    data object RequestCompressionNotSupported : RequestEncryptionError

    data class UnsupportedRequestCompressionMethod(
        val compressionAlgorithm: CompressionAlgorithm,
        val compressionMethodsSupported: NonEmptySet<CompressionAlgorithm>?,
    ) : RequestEncryptionError
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

private typealias IssRequest = Either<CredentialRequestTO, String>
private typealias IssError = Either<RequestEncryptionError, IssueCredentialError>

private val log = LoggerFactory.getLogger(IssueCredential::class.java)

/**
 * Usecase for issuing a Credential.
 */
class IssueCredential(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    resolveCredentialRequestByCredentialIdentifier: ResolveCredentialRequestByCredentialIdentifier,
    private val encryptCredentialResponse: EncryptCredentialResponse,
    validateProof: ValidateProof,
    clock: Clock,
) {
    private val services: Services =
        Services(credentialIssuerMetadata, resolveCredentialRequestByCredentialIdentifier, validateProof, clock)

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
        plainOrEncrypted: IssRequest,
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
                log.warn("Failed to issue credential $error")
                error.response()
            },
            catch = { exception ->
                log.error("Unexpected error while issuing credential", exception)
                throw exception
            },
        )

    context(_: Raise<IssError>)
    private suspend fun issueCredential(
        authorizationContext: AuthorizationContext,
        credentialRequestTO: CredentialRequestTO,
    ): IssueCredentialResponse =
        withError(transform = { Either.Right(it) }) {
            val (request, issued) =
                services.issueCredential(authorizationContext, credentialRequestTO)
            issued.successResponse(request.credentialResponseEncryption)
        }

    private suspend fun CredentialResponse.successResponse(encryption: RequestedResponseEncryption): IssueCredentialResponse {
        val plain = toTO()
        return when (encryption) {
            RequestedResponseEncryption.NotRequired -> plain
            is RequestedResponseEncryption.Required -> encryptCredentialResponse(plain, encryption)
        }
    }
}

//
// Pre-Processing
//

context(_: Raise<IssError>, credentialIssuerMetadata: CredentialIssuerMetaData)
private suspend fun IssRequest.decryptIfNeeded(): CredentialRequestTO =
    withError(transform = { it.left() }) {
        fun CredentialRequestTO.verifyPlainRequestAgainstEncryptionRequirements() {
            ensure(credentialResponseEncryption == null) {
                ResponseEncryptionRequiresEncryptedRequest
            }
            ensure(credentialIssuerMetadata.credentialRequestEncryption !is CredentialRequestEncryption.Required) {
                RequestEncryptionIsRequired
            }
        }

        suspend fun String.decrypt(): CredentialRequestTO = decryptCredentialRequest(this)

        return fold(
            ifLeft = { plain -> plain.apply { verifyPlainRequestAgainstEncryptionRequirements() } },
            ifRight = { encrypted -> encrypted.decrypt() },
        )
    }

private class Services(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val resolveCredentialRequestByCredentialIdentifier: ResolveCredentialRequestByCredentialIdentifier,
    private val validateProof: ValidateProof,
    private val clock: Clock,
) {
    context(_: Raise<IssueCredentialError>)
    suspend fun issueCredential(
        authorizationContext: AuthorizationContext,
        credentialRequestTO: CredentialRequestTO,
    ): Pair<CredentialRequest, CredentialResponse> {
        logRequest(credentialRequestTO)
        val unresolvedRequest =
            credentialRequestTO.toDomain(
                credentialIssuerMetadata.credentialResponseEncryption,
                credentialIssuerMetadata.batchCredentialIssuance,
                credentialIssuerMetadata.credentialConfigurationsSupported,
            )

        val preferredClientStatusPeriod = credentialIssuerMetadata.preferredClientStatusPeriod.value
        ensure((authorizationContext.clientStatus.expiresAt - clock.now()) >= preferredClientStatusPeriod) {
            InvalidClientStatus("Client Status expires before preferred client status period")
        }

        val request =
            when (unresolvedRequest) {
                is UnresolvedCredentialRequest.ByCredentialConfigurationId -> {
                    ResolvedCredentialRequest(
                        unresolvedRequest.credentialConfigurationId,
                        unresolvedRequest.credentialRequest,
                        null,
                    )
                }

                is UnresolvedCredentialRequest.ByCredentialIdentifier -> {
                    resolve(unresolvedRequest)
                }
            }
        val issued = issue(authorizationContext, request)
        return request.credentialRequest to issued
    }

    private fun logRequest(credentialRequestTO: CredentialRequestTO) {
        val credentialConfigurationIdOrCredentialIdentifier =
            credentialRequestTO.credentialConfigurationId
                ?: credentialRequestTO.credentialIdentifier
        log.info("Handling issuance request for $credentialConfigurationIdOrCredentialIdentifier..")
    }

    context(_: Raise<InvalidCredentialIdentifier>)
    private suspend fun resolve(unresolvedRequest: UnresolvedCredentialRequest.ByCredentialIdentifier): ResolvedCredentialRequest {
        val resolvedRequest =
            resolveCredentialRequestByCredentialIdentifier(
                unresolvedRequest.credentialIdentifier,
                unresolvedRequest.unvalidatedProofs,
                unresolvedRequest.credentialResponseEncryption,
            )
        return ensureNotNull(resolvedRequest) {
            InvalidCredentialIdentifier(unresolvedRequest.credentialIdentifier)
        }
    }

    context(_: Raise<IssueCredentialError>)
    private suspend fun issue(
        authorizationContext: AuthorizationContext,
        resolvedCredentialRequest: ResolvedCredentialRequest,
    ): CredentialResponse {
        val issueSpecificCredential = specificIssuerFor(authorizationContext, resolvedCredentialRequest)
        val (_, credentialRequest, credentialIdentifier) = resolvedCredentialRequest
        val validatedProof = issueSpecificCredential.validateProof(credentialRequest)
        return issueSpecificCredential(authorizationContext, credentialRequest, credentialIdentifier, validatedProof)
    }

    context(_: Raise<IssueCredentialError>)
    private suspend fun IssueSpecificCredential.validateProof(credentialRequest: CredentialRequest): ValidatedProof =
        context(supportedCredential) {
            validateProof(
                credentialRequest.unvalidatedProof,
                clock.now(),
            )
        }

    context(_: Raise<IssueCredentialError>)
    private fun specificIssuerFor(
        authorizationContext: AuthorizationContext,
        resolvedCredentialRequest: ResolvedCredentialRequest,
    ): IssueSpecificCredential {
        val credentialRequest = resolvedCredentialRequest.credentialRequest
        val specificIssuers =
            credentialIssuerMetadata.specificCredentialIssuers
                .filter { issuer ->
                    either {
                        assertIsSupported(credentialRequest, issuer.supportedCredential)
                    }.isRight()
                }
        ensure(specificIssuers.isNotEmpty()) {
            val types =
                when (credentialRequest) {
                    is MsoMdocCredentialRequest -> listOf(credentialRequest.docType)
                    is SdJwtVcCredentialRequest -> listOf(credentialRequest.type).map { it.value }
                }
            UnsupportedCredentialType(credentialRequest.format, types)
        }

        val specificIssuer =
            specificIssuers.find { issuer ->
                issuer.supportedCredential.id == resolvedCredentialRequest.credentialConfigurationId
            }
        ensureNotNull(specificIssuer) {
            UnsupportedCredentialConfigurationId(resolvedCredentialRequest.credentialConfigurationId)
        }
        ensure(specificIssuer.supportedCredential.scope in authorizationContext.scopes) {
            WrongScope(specificIssuer.supportedCredential.scope)
        }

        return specificIssuer
    }
}
//
// Mapping to domain
//

/**
 * An unresolved Credential Request.
 */
private sealed interface UnresolvedCredentialRequest {
    /**
     * A Credential Request placed by Credential Configuration Id.
     */
    data class ByCredentialConfigurationId(
        val credentialConfigurationId: CredentialConfigurationId,
        val credentialRequest: CredentialRequest,
    ) : UnresolvedCredentialRequest

    /**
     * A Credential Request placed by Credential Identifier.
     */
    data class ByCredentialIdentifier(
        val credentialIdentifier: CredentialIdentifier,
        val unvalidatedProofs: UnvalidatedProof,
        val credentialResponseEncryption: RequestedResponseEncryption,
    ) : UnresolvedCredentialRequest
}

/**
 * Tries to convert a [CredentialRequestTO] to a [CredentialRequest].
 */
context(_: Raise<IssueCredentialError>)
private suspend fun CredentialRequestTO.toDomain(
    supportedEncryption: CredentialResponseEncryption,
    supportedBatchIssuance: BatchCredentialIssuance,
    supportedCredentialConfigurations: List<CredentialConfiguration>,
): UnresolvedCredentialRequest {
    if (supportedBatchIssuance is BatchCredentialIssuance.NotSupported) {
        ensure(proofs == null) {
            InvalidProof("Credential Endpoint does not support Batch Issuance")
        }
    }

    val proof =
        when {
            proofs != null -> {
                val jwtProofs = proofs.jwtProofs?.map { UnvalidatedProof.Jwt(it) }
                val attestations = proofs.attestations?.map { UnvalidatedProof.Attestation(it) }
                // Proof object contains exactly one parameter named as the proof type
                ensure(1 == listOfNotNull(jwtProofs, attestations).size) {
                    InvalidProof("Only a single proof type is allowed")
                }

                val proofs = (jwtProofs.orEmpty() + attestations.orEmpty()).toNonEmptyListOrNull()
                ensureNotNull(proofs) { MissingProof }
                ensure(proofs.size == 1) {
                    InvalidProof("You can provide at most 1 proof")
                }
                proofs.first()
            }

            else -> {
                raise(MissingProof)
            }
        }

    val credentialResponseEncryption =
        credentialResponseEncryption?.toDomain() ?: RequestedResponseEncryption.NotRequired
    credentialResponseEncryption.ensureIsSupported(supportedEncryption)

    fun credentialRequestByCredentialConfigurationId(
        credentialConfigurationId: CredentialConfigurationId,
    ): UnresolvedCredentialRequest.ByCredentialConfigurationId =
        supportedCredentialConfigurations
            .firstOrNull { credentialConfigurationId == it.id }
            ?.let { credentialConfiguration ->
                val credentialRequest =
                    when (credentialConfiguration) {
                        is MsoMdocCredentialConfiguration -> {
                            credentialConfiguration.credentialRequest(proof, credentialResponseEncryption)
                        }

                        is SdJwtVcCredentialConfiguration -> {
                            credentialConfiguration.credentialRequest(proof, credentialResponseEncryption)
                        }

                        is JwtVcJsonCredentialConfiguration -> {
                            raise(UnsupportedCredentialType(format = JWT_VS_JSON_FORMAT))
                        }
                    }
                UnresolvedCredentialRequest.ByCredentialConfigurationId(
                    credentialConfigurationId,
                    credentialRequest,
                )
            } ?: raise(UnsupportedCredentialConfigurationId(credentialConfigurationId))

    fun credentialRequestByCredentialIdentifier(credentialIdentifier: String): UnresolvedCredentialRequest.ByCredentialIdentifier =
        UnresolvedCredentialRequest.ByCredentialIdentifier(
            CredentialIdentifier(credentialIdentifier),
            proof,
            credentialResponseEncryption,
        )

    val credentialConfigurationIdOrCredentialIdentifier =
        Ior.fromNullables(
            credentialConfigurationId,
            credentialIdentifier,
        ) ?: raise(MissingBothCredentialConfigurationIdAndCredentialIdentifier)
    return credentialConfigurationIdOrCredentialIdentifier.fold(
        {
            val credentialConfigurationId = CredentialConfigurationId(it)
            credentialRequestByCredentialConfigurationId(credentialConfigurationId)
        },
        { credentialIdentifier -> credentialRequestByCredentialIdentifier(credentialIdentifier) },
        { _, _ -> raise(BothCredentialConfigurationIdAndCredentialIdentifierProvided) },
    )
}

/**
 * Gets the [RequestedResponseEncryption] that corresponds to the provided values.
 */
context(_: Raise<IssueCredentialError.InvalidEncryptionParameters>)
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
                // credential response encryption not supported by issuer but required by client
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

fun CredentialResponse.toTO(): IssueCredentialResponse.PlainTO =
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

private fun IssError.response(): IssueCredentialResponse.FailedTO =
    fold(
        ifLeft = { encryptionError -> encryptionError.toTO() },
        ifRight = { credentialError -> credentialError.toTO() },
    )

/**
 * Creates a new [IssueCredentialResponse.FailedTO] from the provided [error].
 */
private fun IssueCredentialError.toTO(): IssueCredentialResponse.FailedTO {
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

            is InvalidClientStatus -> {
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
                    errorDescriptionWithErrorCauseDescription("'claims' does not have the expected structure", error)
                CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to description
            }

            AttestationDatasetNotFound -> {
                val description = "Attestation Dataset not found"
                CredentialErrorTypeTo.ATTESTATION_DATASET_NOT_FOUND to description
            }
        }
    return IssueCredentialResponse.FailedTO(type, description)
}

internal fun errorDescriptionWithErrorCauseDescription(
    description: String,
    cause: Throwable?,
): String =
    buildString {
        append(description)
        if (null != cause && !cause.message.isNullOrBlank()) {
            append(": ${cause.message}")
        }
    }

private fun RequestEncryptionError.toTO(): IssueCredentialResponse.FailedTO {
    val (type, description) =
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
    return IssueCredentialResponse.FailedTO(type, description)
}
