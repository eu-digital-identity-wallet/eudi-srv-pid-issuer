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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptyList
import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.ensure
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK

/**
 * Proof of possession.
 */
sealed interface UnvalidatedProof {
    /**
     * Proof of possession using a JWT.
     */
    data class Jwt(
        val jwt: String,
    ) : UnvalidatedProof

    /**
     * A JWT representing a key attestation without using a proof of possession of
     * the cryptographic key material that is being attested.
     */
    data class Attestation(
        val jwt: String,
    ) : UnvalidatedProof
}

data class ValidatedProof(
    val credentialKeys: CredentialKeys,
    val cNonce: String,
    val keyStorageStatus: KeyStorageStatus,
)

/**
 * This is the public key or reference to it
 * that is provided by the wallet, via [UnvalidatedProof], to be included
 * inside the issued credential
 */
@JvmInline
value class CredentialKeys(
    val value: NonEmptyList<JWK>,
) {
    init {
        value.forEach { it.ensureIsPublicAsymmetricKey() }
        require(value.size == value.distinct().size) { "Duplicate keys provided in credential request" }
    }

    companion object {
        private fun JWK.ensureIsPublicAsymmetricKey() {
            require(!isPrivate) {
                "Private key provided while expecting a public key."
            }
            require(this is AsymmetricJWK) {
                "Symmetric key provided. Must be an asymmetric key."
            }
        }
    }
}

sealed interface RequestedResponseEncryption {
    /**
     * Credential response encryption is not required.
     */
    data object NotRequired : RequestedResponseEncryption

    /**
     * Credential response encryption is required.
     *
     * [encryptionJwk]: A JSON object containing a single public key as a JWK
     * used for encrypting the Credential Response
     *
     * [encryptionMethod]: JWE RFC7516 enc algorithm RFC7518 REQUIRED
     * for encrypting Credential Responses.
     * If credential_response_encryption_alg is specified, the default for this value is A256GCM.
     *
     */
    data class Required private constructor(
        val encryptionJwk: JWK,
        val encryptionMethod: EncryptionMethod,
        val compressionAlgorithm: CompressionAlgorithm? = null,
    ) : RequestedResponseEncryption {
        init {
            require(!encryptionJwk.isPrivate) { "encryptionJwk must not contain a private key" }
            requireNotNull(encryptionJwk.algorithm) {
                "encryptionJwk must have an 'alg' (algorithm) parameter"
            }
            require(encryptionJwk.algorithm in JWEAlgorithm.Family.ASYMMETRIC) {
                "encryptionAlgorithm is not an asymmetric encryption algorithm"
            }
        }

        val encryptionAlgorithm: JWEAlgorithm
            get() = JWEAlgorithm(encryptionJwk.algorithm.name)

        companion object {
            context(_: Raise<String>)
            operator fun invoke(
                encryptionKey: JWK,
                encryptionMethod: String,
                compressionAlgorithm: String? = null,
            ): Required {
                ensure(!encryptionKey.isPrivate) { "encryptionJwk must not contain a private key" }
                ensureNotNull(encryptionKey.algorithm) {
                    "encryptionJwk must have an 'alg' parameter present"
                }
                ensure(encryptionKey.algorithm in JWEAlgorithm.Family.ASYMMETRIC) {
                    "encryptionAlgorithm is not an asymmetric encryption algorithm"
                }
                val method = EncryptionMethod.parse(encryptionMethod)
                val zipMethod = compressionAlgorithm?.let { CompressionAlgorithm(it) }
                return Required(encryptionKey, method, zipMethod)
            }
        }
    }
}

/**
 * A Credential Request.
 */
sealed interface CredentialRequest {
    val format: Format
    val unvalidatedProof: UnvalidatedProof
    val credentialResponseEncryption: RequestedResponseEncryption
}

fun Raise<String>.assertIsSupported(
    credentialRequest: CredentialRequest,
    meta: CredentialConfiguration,
) {
    when (credentialRequest) {
        is MsoMdocCredentialRequest -> {
            ensure(meta is MsoMdocCredentialConfiguration) { "Was expecting a ${MSO_MDOC_FORMAT.value}" }
            validate(credentialRequest, meta)
        }

        is SdJwtVcCredentialRequest -> {
            ensure(meta is SdJwtVcCredentialConfiguration) { "Was expecting a ${SD_JWT_VC_FORMAT.value}" }
            validate(credentialRequest, meta)
        }
    }
}

/**
 * A resolved Credential Request
 */
data class ResolvedCredentialRequest(
    val credentialConfigurationId: CredentialConfigurationId,
    val credentialRequest: CredentialRequest,
    val credentialIdentifier: CredentialIdentifier?,
)
