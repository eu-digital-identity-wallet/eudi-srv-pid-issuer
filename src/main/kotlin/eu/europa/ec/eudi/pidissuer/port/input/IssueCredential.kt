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
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateCNonce
import eu.europa.ec.eudi.pidissuer.port.out.credential.ResolveCredentialRequestByCredentialIdentifier
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Duration

@Serializable
enum class FormatTO {
    @SerialName(MSO_MDOC_FORMAT_VALUE)
    MsoMdoc,

    @SerialName(SD_JWT_VC_FORMAT_VALUE)
    SdJwtVc,
}

@Serializable
enum class ProofTypeTO {
    @SerialName("jwt")
    JWT,

    @SerialName("ldp_vp")
    LDP_VP,
}

@Serializable
data class ProofTo(
    @SerialName("proof_type") @Required val type: ProofTypeTO,
    val jwt: String? = null,
    @SerialName("ldp_vp")
    val ldpVp: String? = null,
)

@Serializable
data class ProofsTO(
    @SerialName("jwt") val jwtProofs: List<String>? = null,
    @SerialName("ldp_vp") val ldpVpProofs: List<String>? = null,
)

@Serializable
data class CredentialResponseEncryptionTO(
    @SerialName("jwk") @Required val key: JsonObject,
    @SerialName("alg") @Required val algorithm: String,
    @SerialName("enc") @Required val method: String,
)

typealias ClaimsTO = Map<String, JsonElement>

@Serializable
data class CredentialRequestTO(
    val format: FormatTO? = null,
    val proof: ProofTo? = null,
    val proofs: ProofsTO? = null,
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
    @SerialName("doctype")
    val docType: String? = null,
    @SerialName("vct")
    val type: String? = null,
    val claims: ClaimsTO? = null,
)

/**
 * Errors that might be raised while trying to issue a credential.
 */
sealed interface IssueCredentialError {

    /**
     * Indicates that both 'format' and 'credential_identifier' was missing from a Credential Request.
     */
    data object MissingBothFormatAndCredentialIdentifier : IssueCredentialError

    /**
     * Indicates that a Credential Request erroneously contained both 'format' and 'credential_identifier'.
     */
    data object BothFormatAndCredentialIdentifierProvided : IssueCredentialError

    /**
     * Indicates that a Credential Request contained Credential Format specific parameters when 'credential_identifier'
     * was provided.
     */
    data class NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided(
        val parameters: NonEmptySet<String>,
    ) : IssueCredentialError {
        companion object {
            operator fun invoke(parameter: String): NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided =
                NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided(nonEmptySetOf(parameter))
        }
    }

    /**
     * Indicates a credential request contained an unsupported 'format'.
     */
    data class UnsupportedCredentialFormat(val format: Format? = null) : IssueCredentialError

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

    @SerialName("invalid_request")
    INVALID_REQUEST,

    @SerialName("invalid_token")
    INVALID_TOKEN,

    @SerialName("unsupported_credential_type")
    UNSUPPORTED_CREDENTIAL_TYPE,

    @SerialName("unsupported_credential_format")
    UNSUPPORTED_CREDENTIAL_FORMAT,

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
        val credential: JsonElement? = null,
        val credentials: JsonArray? = null,
        @SerialName("transaction_id") val transactionId: String? = null,
        @SerialName("c_nonce") val nonce: String? = null,
        @SerialName("c_nonce_expires_in") val nonceExpiresIn: Long? = null,
        @SerialName("notification_id") val notificationId: String? = null,
    ) : IssueCredentialResponse {
        init {
            if (transactionId != null) {
                require(credential == null && credentials == null) {
                    "cannot provide credential or credentials when transactionId is provided"
                }
                require(notificationId == null) {
                    "cannot provide notificationId when transactionId is provided"
                }
            } else {
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
        }

        companion object {

            /**
             * A single credential has been issued.
             */
            fun single(
                credential: JsonElement,
                nonce: String,
                nonceExpiresIn: Long,
                notificationId: String? = null,
            ): PlainTO = PlainTO(
                credential = credential,
                nonce = nonce,
                nonceExpiresIn = nonceExpiresIn,
                notificationId = notificationId,
            )

            /**
             * Multiple credentials have been issued.
             */
            fun multiple(
                credentials: JsonArray,
                nonce: String,
                nonceExpiresIn: Long,
                notificationId: String? = null,
            ): PlainTO = PlainTO(
                credentials = credentials,
                nonce = nonce,
                nonceExpiresIn = nonceExpiresIn,
                notificationId = notificationId,
            )

            /**
             * Credential issuance has been deferred.
             */
            fun deferred(
                transactionId: String,
                nonce: String,
                nonceExpiresIn: Long,
            ): PlainTO = PlainTO(
                transactionId = transactionId,
                nonce = nonce,
                nonceExpiresIn = nonceExpiresIn,
            )
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
        @SerialName("c_nonce") val nonce: String? = null,
        @SerialName("c_nonce_expires_in") val nonceExpiresIn: Long? = null,
    ) : IssueCredentialResponse
}

private val log = LoggerFactory.getLogger(IssueCredential::class.java)

/**
 * Usecase for issuing a Credential.
 */
class IssueCredential(
    private val clock: Clock,
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val resolveCredentialRequestByCredentialIdentifier: ResolveCredentialRequestByCredentialIdentifier,
    private val generateCNonce: GenerateCNonce,
    private val cnonceExpiresIn: Duration = Duration.ofMinutes(5L),
    private val encryptCredentialResponse: EncryptCredentialResponse,
) {

    suspend operator fun invoke(
        authorizationContext: AuthorizationContext,
        credentialRequestTO: CredentialRequestTO,
    ): IssueCredentialResponse = coroutineScope {
        either {
            log.info("Handling issuance request for ${credentialRequestTO.format}..")
            val unresolvedRequest = credentialRequestTO.toDomain(
                credentialIssuerMetadata.credentialResponseEncryption,
                credentialIssuerMetadata.batchCredentialIssuance,
            )
            val (request, credentialIdentifier) =
                when (unresolvedRequest) {
                    is UnresolvedCredentialRequest.ByFormat ->
                        unresolvedRequest.credentialRequest to null

                    is UnresolvedCredentialRequest.ByCredentialIdentifier ->
                        resolve(unresolvedRequest) to unresolvedRequest.credentialIdentifier
                }
            val issued = issue(authorizationContext, request, credentialIdentifier)
            successResponse(request, issued)
        }.getOrElse { error ->
            errorResponse(error)
        }
    }

    context(Raise<IssueCredentialError>)
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

    context(Raise<IssueCredentialError>)
    private suspend fun issue(
        authorizationContext: AuthorizationContext,
        credentialRequest: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): CredentialResponse {
        val issueSpecificCredential = specificIssuerFor(credentialRequest)
        val expectedScope = checkNotNull(issueSpecificCredential.supportedCredential.scope)
        ensure(authorizationContext.scopes.contains(expectedScope)) { WrongScope(expectedScope) }
        return issueSpecificCredential(authorizationContext, credentialRequest, credentialIdentifier)
    }

    context(Raise<IssueCredentialError>)
    private fun specificIssuerFor(credentialRequest: CredentialRequest): IssueSpecificCredential {
        val specificIssuer = credentialIssuerMetadata.specificCredentialIssuers
            .find { issuer ->
                either { credentialRequest.assertIsSupported(issuer.supportedCredential) }.isRight()
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

    private suspend fun successResponse(
        request: CredentialRequest,
        credential: CredentialResponse,
    ): IssueCredentialResponse {
        val newCNonce = generateCNonce(clock.instant(), cnonceExpiresIn)
        val plain = credential.toTO(newCNonce, cnonceExpiresIn)
        return when (val encryption = request.credentialResponseEncryption) {
            RequestedResponseEncryption.NotRequired -> plain
            is RequestedResponseEncryption.Required -> encryptCredentialResponse(plain, encryption).getOrThrow()
        }
    }

    private suspend fun errorResponse(
        error: IssueCredentialError,
    ): IssueCredentialResponse {
        log.warn("Issuance failed: $error")
        val newCNonce = generateCNonce(clock.instant(), cnonceExpiresIn)
        return error.toTO(newCNonce, cnonceExpiresIn)
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
     * A Credential Request placed by Format.
     */
    data class ByFormat(val credentialRequest: CredentialRequest) : UnresolvedCredentialRequest

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

/**
 * Tries to convert a [CredentialRequestTO] to a [CredentialRequest].
 */
context(Raise<IssueCredentialError>)
private fun CredentialRequestTO.toDomain(
    supportedEncryption: CredentialResponseEncryption,
    supportedBatchIssuance: BatchCredentialIssuance,
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
                // proofs object contains exactly one parameter named as the proof type
                ensure(jwtProofs == null || ldpVpProofs == null) {
                    InvalidProof("Only a single proof type is allowed")
                }

                val proofs = (jwtProofs.orEmpty() + ldpVpProofs.orEmpty()).toNonEmptyListOrNull()
                ensureNotNull(proofs) { MissingProof }
            }

            proof != null && proofs != null -> raise(InvalidProof("Only one of `proof` or `proofs` is allowed"))
            else -> raise(MissingProof)
        }
    ensure(proofs.size <= supportedBatchIssuance.maxProofsSupported) {
        InvalidProof("You can provide at most '${supportedBatchIssuance.maxProofsSupported}' proofs")
    }

    val credentialResponseEncryption =
        credentialResponseEncryption?.toDomain() ?: RequestedResponseEncryption.NotRequired
    credentialResponseEncryption.ensureIsSupported(supportedEncryption)

    fun credentialRequestByFormat(format: FormatTO): UnresolvedCredentialRequest.ByFormat =
        when (format) {
            FormatTO.MsoMdoc -> {
                val docType = run {
                    ensure(!docType.isNullOrBlank()) { UnsupportedCredentialType(format = MSO_MDOC_FORMAT) }
                    docType
                }
                val claims = claims?.decodeAs<Map<String, Map<String, JsonObject>>>()
                    ?.mapValues { (_, vs) -> vs.map { it.key } }
                    ?: emptyMap()
                UnresolvedCredentialRequest.ByFormat(
                    MsoMdocCredentialRequest(
                        proofs,
                        credentialResponseEncryption,
                        docType,
                        claims,
                    ),
                )
            }

            FormatTO.SdJwtVc -> {
                val type = run {
                    ensure(!type.isNullOrBlank()) { UnsupportedCredentialType(format = SD_JWT_VC_FORMAT) }
                    type
                }
                val claims = claims?.decodeAs<Map<String, JsonObject>>()?.keys ?: emptySet()

                UnresolvedCredentialRequest.ByFormat(
                    SdJwtVcCredentialRequest(
                        proofs,
                        credentialResponseEncryption,
                        SdJwtVcType(type),
                        claims,
                    ),
                )
            }
        }

    fun credentialRequestByCredentialIdentifier(credentialIdentifier: String): UnresolvedCredentialRequest.ByCredentialIdentifier {
        ensure(docType == null) { NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided("doctype") }
        ensure(claims == null) { NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided("claims") }
        ensure(type == null) { NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided("vct") }

        return UnresolvedCredentialRequest.ByCredentialIdentifier(
            CredentialIdentifier(credentialIdentifier),
            proofs,
            credentialResponseEncryption,
        )
    }

    val formatOrCredentialIdentifier =
        Ior.fromNullables(format, credentialIdentifier) ?: raise(MissingBothFormatAndCredentialIdentifier)
    return formatOrCredentialIdentifier.fold(
        { format -> credentialRequestByFormat(format) },
        { credentialIdentifier -> credentialRequestByCredentialIdentifier(credentialIdentifier) },
        { _, _ -> raise(BothFormatAndCredentialIdentifierProvided) },
    )
}

context(Raise<InvalidClaims>)
private inline fun <reified T> ClaimsTO.decodeAs(): T =
    Either.catch { Json.decodeFromString<T>(Json.encodeToString(this)) }.getOrElse { raise(InvalidClaims(it)) }

/**
 * Gets the [UnvalidatedProof] that corresponds to this [ProofTo].
 */
context (Raise<IssueCredentialError>)
private fun ProofTo.toDomain(): UnvalidatedProof = when (type) {
    ProofTypeTO.JWT -> {
        ensure(!jwt.isNullOrEmpty()) { MissingProof }
        UnvalidatedProof.Jwt(jwt)
    }

    ProofTypeTO.LDP_VP -> {
        ensureNotNull(ldpVp) { MissingProof }
        UnvalidatedProof.LdpVp(ldpVp)
    }
}

/**
 * Verifies this [RequestedResponseEncryption] is supported by the provided [CredentialResponseEncryption], otherwise
 * raises an [InvalidEncryptionParameters].
 */
context(Raise<InvalidEncryptionParameters>)
private fun RequestedResponseEncryption.ensureIsSupported(supported: CredentialResponseEncryption) {
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
                ensure(encryptionAlgorithm in supported.parameters.algorithmsSupported) {
                    InvalidEncryptionParameters(
                        IllegalArgumentException("jwe encryption algorithm '${encryptionAlgorithm.name}' is not supported"),
                    )
                }
                ensure(encryptionMethod in supported.parameters.methodsSupported) {
                    InvalidEncryptionParameters(
                        IllegalArgumentException("jwe encryption method '${encryptionMethod.name}' is not supported"),
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
            ensure(encryptionAlgorithm in supported.parameters.algorithmsSupported) {
                InvalidEncryptionParameters(
                    IllegalArgumentException("jwe encryption algorithm '${encryptionAlgorithm.name}' is not supported"),
                )
            }
            ensure(encryptionMethod in supported.parameters.methodsSupported) {
                InvalidEncryptionParameters(
                    IllegalArgumentException("jwe encryption method '${encryptionMethod.name}' is not supported"),
                )
            }
        }
    }
}

/**
 * Gets the [RequestedResponseEncryption] that corresponds to the provided values.
 */
context(Raise<InvalidEncryptionParameters>)
private fun CredentialResponseEncryptionTO.toDomain(): RequestedResponseEncryption.Required =
    RequestedResponseEncryption.Required(
        Json.encodeToString(key),
        algorithm,
        method,
    ).getOrElse { raise(InvalidEncryptionParameters(it)) }

fun CredentialResponse.toTO(cnonce: String, cnonceExpiresIn: Duration): IssueCredentialResponse.PlainTO = when (this) {
    is CredentialResponse.Issued -> {
        when (credentials.size) {
            1 -> IssueCredentialResponse.PlainTO.single(
                credential = credentials.head,
                nonce = cnonce,
                nonceExpiresIn = cnonceExpiresIn.toSeconds(),
                notificationId = notificationId?.value,
            )

            else -> IssueCredentialResponse.PlainTO.multiple(
                credentials = JsonArray(credentials),
                nonce = cnonce,
                nonceExpiresIn = cnonceExpiresIn.toSeconds(),
                notificationId = notificationId?.value,
            )
        }
    }

    is CredentialResponse.Deferred ->
        IssueCredentialResponse.PlainTO.deferred(
            transactionId = transactionId.value,
            nonce = cnonce,
            nonceExpiresIn = cnonceExpiresIn.toSeconds(),
        )
}

/**
 * Creates a new [IssueCredentialResponse.FailedTO] from the provided [error] and [nonce].
 */
private fun IssueCredentialError.toTO(cnonce: String, cnonceExpiresIn: Duration): IssueCredentialResponse.FailedTO {
    val (type, description) = when (this) {
        is UnsupportedCredentialFormat ->
            CredentialErrorTypeTo.UNSUPPORTED_CREDENTIAL_FORMAT to "Unsupported '${format?.value}'"

        is UnsupportedCredentialType ->
            CredentialErrorTypeTo.UNSUPPORTED_CREDENTIAL_TYPE to "Unsupported format '${format.value}' type `$types`"

        is MissingProof ->
            CredentialErrorTypeTo.INVALID_PROOF to "The Credential Request must include Proof of Possession"

        is InvalidProof ->
            (CredentialErrorTypeTo.INVALID_PROOF to msg).also { println(this@toTO.cause) }

        is InvalidEncryptionParameters ->
            CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS to "Invalid Credential Response Encryption Parameters"

        is WrongScope ->
            CredentialErrorTypeTo.INVALID_REQUEST to "Wrong scope. Expecting $expected"

        is Unexpected ->
            CredentialErrorTypeTo.INVALID_REQUEST to "$msg${cause?.message?.let { " : $it" } ?: ""}"

        is MissingBothFormatAndCredentialIdentifier ->
            CredentialErrorTypeTo.INVALID_REQUEST to "Either 'format' or 'credential_identifier' must be provided"

        is BothFormatAndCredentialIdentifierProvided ->
            CredentialErrorTypeTo.INVALID_REQUEST to "Only one of 'format' or 'credential_identifier' must be provided"

        is NoCredentialFormatSpecificParametersWhenCredentialIdentifierProvided ->
            CredentialErrorTypeTo.INVALID_REQUEST to
                "'${parameters.joinToString(", ")}' must not be provided when 'credential_identifier' is present"

        is InvalidCredentialIdentifier ->
            CredentialErrorTypeTo.INVALID_REQUEST to "'${credentialIdentifier.value}' is not a valid Credential Identifier"

        is InvalidClaims ->
            CredentialErrorTypeTo.INVALID_REQUEST to "'claims' does not have the expected structure${error.message?.let { " : $it" } ?: ""}"
    }
    return IssueCredentialResponse.FailedTO(
        type,
        description,
        cnonce,
        cnonceExpiresIn.toSeconds(),
    )
}
