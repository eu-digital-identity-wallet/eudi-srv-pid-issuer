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

import arrow.core.*
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.*
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.credential.ResolveCredentialRequestByCredentialIdentifier
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory

@Serializable
enum class ProofTypeTO {
    @SerialName("jwt")
    JWT,

    @SerialName("ldp_vp")
    LDP_VP,

    @SerialName("attestation")
    ATTESTATION,
}

@Serializable
data class ProofTo(
    @SerialName("proof_type") @Required val type: ProofTypeTO,
    val jwt: String? = null,
    @SerialName("ldp_vp")
    val ldpVp: String? = null,
    val attestation: String? = null,
)

@Serializable
data class ProofsTO(
    @SerialName("jwt") val jwtProofs: List<String>? = null,
    @SerialName("ldp_vp") val ldpVpProofs: List<String>? = null,
    @SerialName("attestation") val attestations: List<String>? = null,
)

@Serializable
data class CredentialResponseEncryptionTO(
    @SerialName("jwk") @Required val key: JsonObject,
    @SerialName("alg") @Required val algorithm: String,
    @SerialName("enc") @Required val method: String,
)

@Serializable
data class CredentialRequestTO(
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    @Deprecated(message = "Will be removed in a future draft.")
    val proof: ProofTo? = null,
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
    data class UnsupportedCredentialConfigurationId(val credentialConfigurationId: CredentialConfigurationId) : IssueCredentialError

    data class UnsupportedCredentialType(
        val format: Format,
        val types: List<String> = emptyList(),
    ) : IssueCredentialError

    /**
     * Indicates that a Credential Request contained an invalid 'credential_identifier'.
     */
    data class InvalidCredentialIdentifier(val credentialIdentifier: CredentialIdentifier) : IssueCredentialError

    /**
     * Indicates that Proof of Possession was not provided.
     */
    data object MissingProof : IssueCredentialError

    /**
     * Indicates the provided 'claims' did not have the expected structure.
     */
    data class InvalidClaims(val error: Throwable) : IssueCredentialError

    /**
     * Indicates a credential request contained an invalid 'jwt' proof.
     */
    data class InvalidProof(val msg: String, val cause: Throwable? = null) : IssueCredentialError

    /**
     * Indicates a credential request contained contains an invalid 'credential_response_encryption_alg'.
     */
    data class InvalidEncryptionParameters(val error: Throwable) : IssueCredentialError

    data class WrongScope(val expected: Scope) : IssueCredentialError

    data class Unexpected(val msg: String, val cause: Throwable? = null) : IssueCredentialError
}

/**
 * An error that occurred during the Credential Issuance.
 */
@Serializable
enum class CredentialErrorTypeTo {

    @SerialName("invalid_credential_request")
    INVALID_CREDENTIAL_REQUEST,

    @SerialName("unsupported_credential_type")
    UNSUPPORTED_CREDENTIAL_TYPE,

    @SerialName("invalid_proof")
    INVALID_PROOF,

    @SerialName("invalid_encryption_parameters")
    INVALID_ENCRYPTION_PARAMETERS,
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
            fun deferred(transactionId: String): PlainTO = PlainTO(transactionId = transactionId)
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

private val log = LoggerFactory.getLogger(IssueCredential::class.java)

/**
 * Usecase for issuing a Credential.
 */
class IssueCredential(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val resolveCredentialRequestByCredentialIdentifier: ResolveCredentialRequestByCredentialIdentifier,
    private val encryptCredentialResponse: EncryptCredentialResponse,
) {

    private fun Raise<IssueCredentialError>.services(): Services =
        Services(this, credentialIssuerMetadata, resolveCredentialRequestByCredentialIdentifier)

    suspend operator fun invoke(
        authorizationContext: AuthorizationContext,
        credentialRequestTO: CredentialRequestTO,
    ): IssueCredentialResponse = coroutineScope {
        either {
            val credentialConfigurationIdOrCredentialIdentifier =
                credentialRequestTO.credentialConfigurationId
                    ?: credentialRequestTO.credentialIdentifier
            log.info("Handling issuance request for $credentialConfigurationIdOrCredentialIdentifier..")
            val(request, issued) =
                services().issueCredential(authorizationContext, credentialRequestTO)
            successResponse(request, issued)
        }.getOrElse { error ->
            errorResponse(error)
        }
    }

    private fun successResponse(
        request: CredentialRequest,
        credential: CredentialResponse,
    ): IssueCredentialResponse {
        val plain = credential.toTO()
        return when (val encryption = request.credentialResponseEncryption) {
            RequestedResponseEncryption.NotRequired -> plain
            is RequestedResponseEncryption.Required -> encryptCredentialResponse(plain, encryption).getOrThrow()
        }
    }

    private fun errorResponse(error: IssueCredentialError): IssueCredentialResponse {
        log.warn("Issuance failed: $error")
        return error.toTO()
    }
}

private class Services(
    raise: Raise<IssueCredentialError>,
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val resolveCredentialRequestByCredentialIdentifier: ResolveCredentialRequestByCredentialIdentifier,
) :
    Validations,
    Raise<IssueCredentialError> by raise {

        suspend fun issueCredential(
            authorizationContext: AuthorizationContext,
            credentialRequestTO: CredentialRequestTO,
        ): Pair<CredentialRequest, CredentialResponse> = coroutineScope {
            val unresolvedRequest =
                credentialRequestTO.toDomain(
                    credentialIssuerMetadata.credentialResponseEncryption,
                    credentialIssuerMetadata.batchCredentialIssuance,
                    credentialIssuerMetadata.credentialConfigurationsSupported,
                )
            val (request, credentialIdentifier) =
                when (unresolvedRequest) {
                    is UnresolvedCredentialRequest.ByCredentialConfigurationId ->
                        unresolvedRequest.credentialRequest to null

                    is UnresolvedCredentialRequest.ByCredentialIdentifier ->
                        resolve(unresolvedRequest) to unresolvedRequest.credentialIdentifier
                }
            val issued = issue(authorizationContext, request, credentialIdentifier)
            request to issued
        }

        private suspend fun resolve(
            unresolvedRequest: UnresolvedCredentialRequest.ByCredentialIdentifier,
        ): CredentialRequest =
            either {
                val resolvedRequest = resolveCredentialRequestByCredentialIdentifier(
                    unresolvedRequest.credentialIdentifier,
                    unresolvedRequest.unvalidatedProofs,
                    unresolvedRequest.credentialResponseEncryption,
                )
                ensureNotNull(resolvedRequest) { InvalidCredentialIdentifier(unresolvedRequest.credentialIdentifier) }
                resolvedRequest
            }.bind()

        private suspend fun issue(
            authorizationContext: AuthorizationContext,
            credentialRequest: CredentialRequest,
            credentialIdentifier: CredentialIdentifier?,
        ): CredentialResponse {
            val issueSpecificCredential = specificIssuerFor(credentialRequest)
            val expectedScope = checkNotNull(issueSpecificCredential.supportedCredential.scope)
            ensure(authorizationContext.scopes.contains(expectedScope)) { WrongScope(expectedScope) }
            return issueSpecificCredential(authorizationContext, credentialRequest, credentialIdentifier).bind()
        }

        private fun specificIssuerFor(credentialRequest: CredentialRequest): IssueSpecificCredential {
            val specificIssuer = credentialIssuerMetadata.specificCredentialIssuers
                .find { issuer ->
                    either { assertIsSupported(credentialRequest, issuer.supportedCredential) }.isRight()
                }
            if (specificIssuer == null) {
                val types = when (credentialRequest) {
                    is MsoMdocCredentialRequest -> listOf(credentialRequest.docType)
                    is SdJwtVcCredentialRequest -> listOf(credentialRequest.type).map { it.value }
                }
                raise(UnsupportedCredentialType(credentialRequest.format, types))
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
    data class ByCredentialConfigurationId(val credentialRequest: CredentialRequest) : UnresolvedCredentialRequest

    /**
     * A Credential Request placed by Credential Identifier.
     */
    data class ByCredentialIdentifier(
        val credentialIdentifier: CredentialIdentifier,
        val unvalidatedProofs: NonEmptyList<UnvalidatedProof>,
        val credentialResponseEncryption: RequestedResponseEncryption,
    ) : UnresolvedCredentialRequest
}

private val BatchCredentialIssuance.maxProofsSupported: Int
    get() = when (this) {
        BatchCredentialIssuance.NotSupported -> 1
        is BatchCredentialIssuance.Supported -> batchSize
    }

private interface Validations : Raise<IssueCredentialError> {

    /**
     * Tries to convert a [CredentialRequestTO] to a [CredentialRequest].
     */
    fun CredentialRequestTO.toDomain(
        supportedEncryption: CredentialResponseEncryption,
        supportedBatchIssuance: BatchCredentialIssuance,
        supportedCredentialConfigurations: List<CredentialConfiguration>,
    ): UnresolvedCredentialRequest {
        if (supportedBatchIssuance is BatchCredentialIssuance.NotSupported) {
            ensure(proofs == null) {
                InvalidProof("Credential Endpoint does not support Batch Issuance")
            }
        }

        val proofs =
            when {
                proof != null && proofs == null -> nonEmptyListOf(proof.toDomain())
                proof == null && proofs != null -> {
                    val jwtProofs = proofs.jwtProofs?.map { UnvalidatedProof.Jwt(it) }
                    val ldpVpProofs = proofs.ldpVpProofs?.map { UnvalidatedProof.LdpVp(it) }
                    val attestations = proofs.attestations?.map { UnvalidatedProof.Attestation(it) }
                        ?.also {
                            ensure(1 == it.size) { InvalidProof("'attestation' can contain only a single element") }
                        }
                    // Proof object contains exactly one parameter named as the proof type
                    ensure(1 == listOfNotNull(jwtProofs, ldpVpProofs, attestations).size) {
                        InvalidProof("Only a single proof type is allowed")
                    }

                    val proofs = (jwtProofs.orEmpty() + ldpVpProofs.orEmpty() + attestations.orEmpty()).toNonEmptyListOrNull()
                    ensureNotNull(proofs) { MissingProof }
                }

                proof != null && proofs != null -> raise(
                    InvalidProof("Only one of `proof` or `proofs` is allowed"),
                )

                else -> raise(MissingProof)
            }
        ensure(proofs.size <= supportedBatchIssuance.maxProofsSupported) {
            InvalidProof("You can provide at most '${supportedBatchIssuance.maxProofsSupported}' proofs")
        }

        val credentialResponseEncryption = credentialResponseEncryption?.toDomain() ?: RequestedResponseEncryption.NotRequired
        credentialResponseEncryption.ensureIsSupported(supportedEncryption)

        fun credentialRequestByCredentialConfigurationId(
            credentialConfigurationId: CredentialConfigurationId,
        ): UnresolvedCredentialRequest.ByCredentialConfigurationId =
            supportedCredentialConfigurations.firstOrNull { credentialConfigurationId == it.id }
                ?.let { credentialConfiguration ->
                    val credentialRequest = when (credentialConfiguration) {
                        is MsoMdocCredentialConfiguration -> credentialConfiguration.credentialRequest(proofs, credentialResponseEncryption)
                        is SdJwtVcCredentialConfiguration -> credentialConfiguration.credentialRequest(proofs, credentialResponseEncryption)
                        is JwtVcJsonCredentialConfiguration -> raise(UnsupportedCredentialType(format = JWT_VS_JSON_FORMAT))
                    }
                    UnresolvedCredentialRequest.ByCredentialConfigurationId(credentialRequest)
                } ?: raise(UnsupportedCredentialConfigurationId(credentialConfigurationId))

        fun credentialRequestByCredentialIdentifier(credentialIdentifier: String): UnresolvedCredentialRequest.ByCredentialIdentifier =
            UnresolvedCredentialRequest.ByCredentialIdentifier(
                CredentialIdentifier(credentialIdentifier),
                proofs,
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
    fun CredentialResponseEncryptionTO.toDomain(): RequestedResponseEncryption.Required =
        RequestedResponseEncryption.Required(
            Json.encodeToString(key),
            algorithm,
            method,
        ).getOrElse { raise(InvalidEncryptionParameters(it)) }

    /**
     * Verifies this [RequestedResponseEncryption] is supported by the provided [CredentialResponseEncryption], otherwise
     * raises an [InvalidEncryptionParameters].
     */
    fun RequestedResponseEncryption.ensureIsSupported(
        supported: CredentialResponseEncryption,
    ) {
        when (supported) {
            is CredentialResponseEncryption.NotSupported -> {
                ensure(this !is RequestedResponseEncryption.Required) {
                    // credential response encryption not supported by issuer but required by client
                    InvalidEncryptionParameters(IllegalArgumentException("credential response encryption is not supported"))
                }
            }

            is CredentialResponseEncryption.Optional -> {
                if (this is RequestedResponseEncryption.Required) {
                    // credential response encryption supported by issuer and required by client
                    // ensure provided parameters are supported
                    ensure(this.encryptionAlgorithm in supported.parameters.algorithmsSupported) {
                        InvalidEncryptionParameters(
                            IllegalArgumentException(
                                "jwe encryption algorithm '${this.encryptionAlgorithm.name}' is not supported",
                            ),
                        )
                    }
                    ensure(this.encryptionMethod in supported.parameters.methodsSupported) {
                        InvalidEncryptionParameters(
                            IllegalArgumentException(
                                "jwe encryption method '${this.encryptionMethod.name}' is not supported",
                            ),
                        )
                    }
                }
            }

            is CredentialResponseEncryption.Required -> {
                ensure(this is RequestedResponseEncryption.Required) {
                    // credential response encryption required by issuer but not required by client
                    InvalidEncryptionParameters(IllegalArgumentException("credential response encryption is required"))
                }

                // ensure provided parameters are supported
                ensure(this.encryptionAlgorithm in supported.parameters.algorithmsSupported) {
                    InvalidEncryptionParameters(
                        IllegalArgumentException(
                            "jwe encryption algorithm '${this.encryptionAlgorithm.name}' is not supported",
                        ),
                    )
                }
                ensure(this.encryptionMethod in supported.parameters.methodsSupported) {
                    InvalidEncryptionParameters(
                        IllegalArgumentException(
                            "jwe encryption method '${this.encryptionMethod.name}' is not supported",
                        ),
                    )
                }
            }
        }
    }

    /**
     * Gets the [UnvalidatedProof] that corresponds to this [ProofTo].
     */
    fun ProofTo.toDomain(): UnvalidatedProof = when (type) {
        ProofTypeTO.JWT -> {
            ensure(!jwt.isNullOrEmpty()) { MissingProof }
            UnvalidatedProof.Jwt(jwt)
        }

        ProofTypeTO.LDP_VP -> {
            ensureNotNull(ldpVp) { MissingProof }
            UnvalidatedProof.LdpVp(ldpVp)
        }

        ProofTypeTO.ATTESTATION -> {
            ensureNotNull(attestation) { MissingProof }
            UnvalidatedProof.Attestation(attestation)
        }
    }
}

fun CredentialResponse.toTO(): IssueCredentialResponse.PlainTO = when (this) {
    is CredentialResponse.Issued -> {
        IssueCredentialResponse.PlainTO.issued(
            credentials = JsonArray(credentials),
            notificationId = notificationId?.value,
        )
    }

    is CredentialResponse.Deferred ->
        IssueCredentialResponse.PlainTO.deferred(transactionId = transactionId.value)
}

/**
 * Creates a new [IssueCredentialResponse.FailedTO] from the provided [error].
 */
private fun IssueCredentialError.toTO(): IssueCredentialResponse.FailedTO {
    val (type, description) = when (this) {
        is UnsupportedCredentialConfigurationId ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                "Unsupported Credential Configuration Id '${credentialConfigurationId.value}'"

        is UnsupportedCredentialType ->
            CredentialErrorTypeTo.UNSUPPORTED_CREDENTIAL_TYPE to "Unsupported format '${format.value}' type `$types`"

        is MissingProof ->
            CredentialErrorTypeTo.INVALID_PROOF to "The Credential Request must include Proof of Possession"

        is InvalidProof ->
            (CredentialErrorTypeTo.INVALID_PROOF to msg)

        is InvalidEncryptionParameters ->
            CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS to "Invalid Credential Response Encryption Parameters"

        is WrongScope ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Wrong scope. Expecting $expected"

        is Unexpected ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "$msg${cause?.message?.let { " : $it" } ?: ""}"

        is MissingBothCredentialConfigurationIdAndCredentialIdentifier ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Either 'format' or 'credential_identifier' must be provided"

        is BothCredentialConfigurationIdAndCredentialIdentifierProvided ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "Only one of 'format' or 'credential_identifier' must be provided"

        is InvalidCredentialIdentifier ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to "'${credentialIdentifier.value}' is not a valid Credential Identifier"

        is InvalidClaims ->
            CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST to
                "'claims' does not have the expected structure${error.message?.let { " : $it" } ?: ""}"
    }
    return IssueCredentialResponse.FailedTO(type, description)
}
