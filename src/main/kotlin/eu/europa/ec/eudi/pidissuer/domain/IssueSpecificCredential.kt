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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.json.JsonElement
import java.security.cert.X509Certificate

/**
 * Proof of possession.
 */
sealed interface UnvalidatedProof {

    /**
     * Proof of possession using a JWT.
     */
    data class Jwt(val jwt: String) : UnvalidatedProof

    /**
     * Proof of possession using a CWT.
     */
    data class Cwt(val cwt: String) : UnvalidatedProof
}

/**
 * This is the public key or reference to it
 * that is provided by the wallet, via [UnvalidatedProof], to be included
 * inside the issued credential
 */
sealed interface CredentialKey {

    /**
     * If the Credential shall be bound to a DID, the kid refers to a DID URL
     * which identifies a particular key in the DID Document that the Credential shall be bound to
     */
    @JvmInline
    value class DIDUrl(val value: String) : CredentialKey

    data class Jwk(val value: JWK) : CredentialKey

    data class X5c(val chain: List<X509Certificate>) : CredentialKey
}

sealed interface RequestedResponseEncryption {

    /**
     */
    data object NotRequired : RequestedResponseEncryption

    /**
     * @param encryptionJwk A JSON object containing a single public key as a JWK
     * used for encrypting the Credential Response
     * @param encryptionAlgorithm  JWE RFC7516 alg algorithm RFC7518 REQUIRED
     * for encrypting Credential and/or Batch Credential Responses
     *
     * @param encryptionMethod  JWE RFC7516 enc algorithm RFC7518 REQUIRED
     * for encrypting Credential Responses.
     * If credential_response_encryption_alg is specified, the default for this value is A256GCM.
     *
     */
    data class Required(
        val encryptionJwk: JWK,
        val encryptionAlgorithm: JWEAlgorithm,
        val encryptionMethod: EncryptionMethod = EncryptionMethod.A256GCM,
    ) : RequestedResponseEncryption

    companion object {
        operator fun invoke(
            encryptionKey: String?,
            encryptionAlgorithm: String?,
            encryptionMethod: String?,
        ): Either<Throwable, RequestedResponseEncryption> = either {
            if (encryptionKey == null && encryptionAlgorithm == null && encryptionMethod == null) NotRequired
            else {
                ensureNotNull(encryptionKey) { IllegalArgumentException("Missing encryption key") }
                ensureNotNull(encryptionAlgorithm) { IllegalArgumentException("Missing encryption algorithm") }
                required(encryptionKey, encryptionAlgorithm, encryptionMethod).bind()
            }
        }

        fun required(
            encryptionKey: String,
            encryptionAlgorithm: String,
            encryptionMethod: String?,
        ): Either<Throwable, Required> = either {
            val credentialResponseEncryptionKey = Either.catch { JWK.parse(encryptionKey) }.bind()
            val credentialResponseEncryptionAlgorithm = Either.catch { JWEAlgorithm.parse(encryptionAlgorithm) }.bind()
            val credentialResponseEncryptionMethod =
                encryptionMethod?.let { Either.catch { EncryptionMethod.parse(it) }.bind() } ?: EncryptionMethod.A256GCM
            Required(
                credentialResponseEncryptionKey,
                credentialResponseEncryptionAlgorithm,
                credentialResponseEncryptionMethod,
            )
        }
    }
}

sealed interface CredentialRequest {
    val format: Format
    val unvalidatedProof: UnvalidatedProof
    val credentialResponseEncryption: RequestedResponseEncryption
}

/**
 * The identifier of a deferred issuance transaction.
 */
@JvmInline
value class TransactionId(val value: String)

/**
 * The response to a Credential Request.
 */
sealed interface CredentialResponse<out T> {

    /**
     * An unencrypted Credential has been issued.
     */
    data class Issued<T>(val credential: T) : CredentialResponse<T>

    /**
     * The issuance of the requested Credential has been deferred.
     * The deferred transaction can be identified by [transactionId].
     */
    data class Deferred(val transactionId: TransactionId) : CredentialResponse<Nothing>
}

sealed interface Err {
    data object UnsupportedResponseEncryptionOptions : Err

    data class Unexpected(val msg: String, val cause: Throwable? = null) : Err

    data class ProofInvalid(val msg: String, val cause: Throwable? = null) : Err
}

context(Raise<String>)
private fun CredentialRequest.assertIsSupported(meta: CredentialMetaData) = when (this) {
    is MsoMdocCredentialRequest -> {
        ensure(meta is MsoMdocMetaData) { "Was expecting a ${MSO_MDOC_FORMAT.value}" }
        validate(meta)
    }

    is SdJwtVcCredentialRequest -> {
        ensure(meta is SdJwtVcMetaData) { "Was expecting a ${SD_JWT_VC_FORMAT.value}" }
        validate(meta)
    }
}

interface IssueSpecificCredential {

    val supportedCredential: CredentialMetaData

    context(Raise<Err>)
    suspend operator fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement>
}
fun IssueSpecificCredential.supports(request: CredentialRequest): Boolean =
    either { request.assertIsSupported(supportedCredential) }.isRight()
