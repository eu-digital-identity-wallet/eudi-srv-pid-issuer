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

import arrow.core.getOrElse
import arrow.core.raise.*
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.*
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenCNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadCNonceByAccessToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.UpsertCNonce
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.time.Clock

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

    @SerialName("cwt")
    CWT,
}

@Serializable
data class ProofTo(
    @SerialName("proof_type") @Required val type: ProofTypeTO,
    val jwt: String? = null,
    val cwt: String? = null,
)

interface CredentialResponseEncryptionTO {
    val credentialResponseEncryptionKey: JsonObject?
    val credentialResponseEncryptionAlgorithm: String?
    val credentialResponseEncryptionMethod: String?
}

@Serializable
data class SdJwtVcCredentialDefinition(
    val type: String?,
    val claims: Map<String, JsonObject>? = null,
)

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("format")
sealed interface CredentialRequestTO {

    @Required
    val format: FormatTO
    val proof: ProofTo?

    @SerialName("credential_encryption_jwk")
    val credentialResponseEncryptionKey: JsonObject?

    @SerialName("credential_response_encryption_alg")
    val credentialResponseEncryptionAlgorithm: String?

    @SerialName("credential_response_encryption_enc")
    val credentialResponseEncryptionMethod: String?
    val credentialResponseEncryption
        get() = object : CredentialResponseEncryptionTO {
            val self = this@CredentialRequestTO
            override val credentialResponseEncryptionKey = self.credentialResponseEncryptionKey
            override val credentialResponseEncryptionAlgorithm = self.credentialResponseEncryptionAlgorithm
            override val credentialResponseEncryptionMethod = self.credentialResponseEncryptionMethod
        }

    /**
     * Transfer object for an MsoMdoc credential request.
     */
    @Serializable
    @SerialName(MSO_MDOC_FORMAT_VALUE)
    data class MsoMdoc(
        @Required override val format: FormatTO = FormatTO.MsoMdoc,
        @SerialName("doctype") @Required
        val docType: String,
        val claims: Map<String, Map<String, JsonObject>>? = null,
        override val proof: ProofTo? = null,
        @SerialName("credential_encryption_jwk")
        override val credentialResponseEncryptionKey: JsonObject? = null,
        @SerialName("credential_response_encryption_alg")
        override val credentialResponseEncryptionAlgorithm: String? = null,
        @SerialName("credential_response_encryption_enc")
        override val credentialResponseEncryptionMethod: String? = null,
    ) : CredentialRequestTO {
        init {
            require(format == FormatTO.MsoMdoc)
        }
    }

    @Serializable
    @SerialName(SD_JWT_VC_FORMAT_VALUE)
    data class SdJwtVc(
        @Required override val format: FormatTO = FormatTO.SdJwtVc,
        @SerialName("credential_definition") @Required
        val credentialDefinition: SdJwtVcCredentialDefinition,
        override val proof: ProofTo? = null,
        @SerialName("credential_encryption_jwk")
        override val credentialResponseEncryptionKey: JsonObject? = null,
        @SerialName("credential_response_encryption_alg")
        override val credentialResponseEncryptionAlgorithm: String? = null,
        @SerialName("credential_response_encryption_enc")
        override val credentialResponseEncryptionMethod: String? = null,
    ) : CredentialRequestTO {
        init {
            require(format == FormatTO.SdJwtVc)
        }
    }
}

/**
 * Errors that might be raised while trying to issue a credential.
 */
sealed interface IssueCredentialError {

    /**
     * Indicates a credential request contained an unsupported 'format'.
     */
    data class UnsupportedCredentialFormat(val format: Format? = null) :
        IssueCredentialError

    data class UnsupportedCredentialType(val format: Format, val types: List<String> = emptyList()) :
        IssueCredentialError

    /**
     * Indicates that Proof of Possession was not provided.
     */
    data object MissingProof : IssueCredentialError

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
        @Required val format: String,
        val credential: JsonElement? = null,
        @SerialName("transaction_id") val transactionId: String? = null,
        @SerialName("c_nonce") val nonce: String? = null,
        @SerialName("c_nonce_expires_in") val nonceExpiresIn: Long? = null,
    ) : IssueCredentialResponse {
        init {
            if (credential != null) {
                require(credential is JsonObject || (credential is JsonPrimitive && credential.isString)) {
                    "credential must either be a JsonObject or a string JsonPrimitive"
                }
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
    private val loadCNonceByAccessToken: LoadCNonceByAccessToken,
    private val genCNonce: GenCNonce,
    private val upsertCNonce: UpsertCNonce,
    private val encryptCredentialResponse: EncryptCredentialResponse,
) {

    suspend operator fun invoke(
        authorizationContext: AuthorizationContext,
        credentialRequestTO: CredentialRequestTO,
    ): IssueCredentialResponse = coroutineScope {
        either {
            log.info("Handling issuance request for ${credentialRequestTO.format}..")
            val request = credentialRequestTO.toDomain(credentialIssuerMetadata.credentialResponseEncryption)
            val issued = issue(authorizationContext, request)
            successResponse(authorizationContext, request, issued)
        }.getOrElse { error ->
            errorResponse(authorizationContext, error)
        }
    }

    context(Raise<IssueCredentialError>)
    private suspend fun issue(
        authorizationContext: AuthorizationContext,
        credentialRequest: CredentialRequest,
    ): CredentialResponse<JsonElement> {
        val issueSpecificCredential = specificIssuerFor(credentialRequest)
        val expectedScope = issueSpecificCredential.supportedCredential.scope!!
        ensure(authorizationContext.scopes.contains(expectedScope)) { WrongScope(expectedScope) }
        val cNonce = loadCNonceByAccessToken(authorizationContext.accessToken, clock)
        ensureNotNull(cNonce) { MissingProof }
        return issueSpecificCredential(authorizationContext, credentialRequest, cNonce)
    }

    context(Raise<UnsupportedCredentialType>)
    private fun specificIssuerFor(credentialRequest: CredentialRequest): IssueSpecificCredential<JsonElement> {
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
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credential: CredentialResponse<JsonElement>,
    ): IssueCredentialResponse {
        val newCNonce = newCNonce(authorizationContext)
        val plain = credential.toTO(request.format, newCNonce)
        return when (val encryption = request.credentialResponseEncryption) {
            RequestedResponseEncryption.NotRequired -> plain
            is RequestedResponseEncryption.Required -> encryptCredentialResponse(plain, encryption).getOrThrow()
        }
    }

    private suspend fun errorResponse(
        authorizationContext: AuthorizationContext,
        error: IssueCredentialError,
    ): IssueCredentialResponse {
        log.warn("Issuance failed: $error")
        val newCNonce = newCNonce(authorizationContext)
        return error.toTO(newCNonce)
    }

    private suspend fun newCNonce(authorizationContext: AuthorizationContext): CNonce {
        val newCNonce = genCNonce(authorizationContext.accessToken, clock)
        return newCNonce.also { upsertCNonce(it) }
    }
}
//
// Mapping to domain
//

/**
 * Tries to parse a [JsonObject] as a [CredentialRequest].
 */
context(Raise<IssueCredentialError>)
fun CredentialRequestTO.toDomain(
    supported: CredentialResponseEncryption,
): CredentialRequest {
    val proof = ensureNotNull(proof) { MissingProof }.toDomain()
    val credentialResponseEncryption = credentialResponseEncryption.toDomain(supported)
    return when (val req = this@toDomain) {
        is CredentialRequestTO.MsoMdoc -> {
            ensure(req.docType.isNotBlank()) { UnsupportedCredentialType(format = MSO_MDOC_FORMAT) }
            MsoMdocCredentialRequest(
                proof,
                credentialResponseEncryption,
                req.docType,
                (req.claims ?: emptyMap()).mapValues { (_, v) -> v.map { it.key } },
            )
        }

        is CredentialRequestTO.SdJwtVc -> {
            val type = req.credentialDefinition.type
            ensure(!type.isNullOrBlank()) { UnsupportedCredentialType(format = SD_JWT_VC_FORMAT) }
            ensureNotNull(proof) { MissingProof }
            // TODO extract the requested attributes
            SdJwtVcCredentialRequest(proof, credentialResponseEncryption, SdJwtVcType(type), emptyList())
        }
    }
}

/**
 * Gets the [UnvalidatedProof] that corresponds to this [ProofTo].
 */
context (Raise<IssueCredentialError>)
private fun ProofTo.toDomain(): UnvalidatedProof = when (type) {
    ProofTypeTO.JWT -> {
        ensure(!jwt.isNullOrEmpty()) { MissingProof }
        UnvalidatedProof.Jwt(jwt)
    }

    ProofTypeTO.CWT -> {
        ensureNotNull(cwt) { MissingProof }
        UnvalidatedProof.Cwt(cwt)
    }
}

/**
 * Gets the [RequestedResponseEncryption] that corresponds to the provided values.
 */
context(Raise<InvalidEncryptionParameters>)
private fun CredentialResponseEncryptionTO.toDomain(
    supported: CredentialResponseEncryption,
): RequestedResponseEncryption {
    val encryptionKey = credentialResponseEncryptionKey?.let { Json.encodeToString(it) }
    return withError({ InvalidEncryptionParameters(it) }) {
        fun RequestedResponseEncryption.ensureIsSupported() {
            when (supported) {
                is CredentialResponseEncryption.NotRequired -> {
                    if (this !is RequestedResponseEncryption.NotRequired) {
                        raise(IllegalArgumentException("credential response encryption is not required"))
                    }
                }

                is CredentialResponseEncryption.Required -> {
                    if (this !is RequestedResponseEncryption.Required) {
                        raise(IllegalArgumentException("credential response encryption is required"))
                    }
                    if (encryptionAlgorithm !in supported.algorithmsSupported) {
                        raise(IllegalArgumentException("jwe algorithm '${encryptionAlgorithm.name}' is not supported"))
                    }
                    if (encryptionMethod !in supported.encryptionMethods) {
                        raise(IllegalArgumentException("jwe encryption method '${encryptionMethod.name}' is not supported"))
                    }
                }
            }
        }

        val requested = RequestedResponseEncryption(
            encryptionKey,
            credentialResponseEncryptionAlgorithm,
            credentialResponseEncryptionMethod,
        ).bind()

        requested.ensureIsSupported()
        requested
    }
}

fun CredentialResponse<JsonElement>.toTO(format: Format, nonce: CNonce): IssueCredentialResponse.PlainTO =
    when (this) {
        is CredentialResponse.Issued ->
            IssueCredentialResponse.PlainTO(
                format = format.value,
                credential = credential,
                nonce = nonce.nonce,
                nonceExpiresIn = nonce.expiresIn.toSeconds(),
            )

        is CredentialResponse.Deferred ->
            IssueCredentialResponse.PlainTO(
                format = format.value,
                transactionId = transactionId.value,
                nonce = nonce.nonce,
                nonceExpiresIn = nonce.expiresIn.toSeconds(),
            )
    }

/**
 * Creates a new [IssueCredentialResponse.FailedTO] from the provided [error] and [nonce].
 */
private fun IssueCredentialError.toTO(nonce: CNonce): IssueCredentialResponse.FailedTO {
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
    }
    return IssueCredentialResponse.FailedTO(
        type,
        description,
        nonce.nonce,
        nonce.expiresIn.toSeconds(),
    )
}
