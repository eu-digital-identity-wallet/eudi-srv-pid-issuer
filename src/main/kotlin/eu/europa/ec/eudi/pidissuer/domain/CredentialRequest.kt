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
import arrow.core.NonEmptyList
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
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

    @JvmInline
    value class Jwk(val value: JWK) : CredentialKey {
        init {
            require(!value.isPrivate) { "jwk must not contain a private key" }
            require(value is AsymmetricJWK) { "'jwk' must be asymmetric" }
        }
    }

    @JvmInline
    value class X5c(val chain: NonEmptyList<X509Certificate>) : CredentialKey {
        val certificate: X509Certificate
            get() = chain.head

        companion object
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
     * [encryptionAlgorithm]: JWE RFC7516 alg algorithm RFC7518 REQUIRED
     * for encrypting Credential and/or Batch Credential Responses
     *
     * [encryptionMethod]: JWE RFC7516 enc algorithm RFC7518 REQUIRED
     * for encrypting Credential Responses.
     * If credential_response_encryption_alg is specified, the default for this value is A256GCM.
     *
     */
    data class Required(
        val encryptionJwk: JWK,
        val encryptionAlgorithm: JWEAlgorithm,
        val encryptionMethod: EncryptionMethod = EncryptionMethod.A256GCM,
    ) : RequestedResponseEncryption {
        init {
            require(!encryptionJwk.isPrivate) { "encryptionJwk must not contain a private key" }
            require(KeyUse.ENCRYPTION == encryptionJwk.keyUse) {
                "encryptionJwk cannot be used for encryption"
            }
            require(encryptionAlgorithm in JWEAlgorithm.Family.ASYMMETRIC) {
                "encryptionAlgorithm is not an asymmetric encryption algorithm"
            }
        }
    }

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
        ): Either<Throwable, Required> =
            Either.catch {
                val key = JWK.parse(encryptionKey)
                val algorithm = JWEAlgorithm.parse(encryptionAlgorithm)
                val method =
                    encryptionMethod
                        ?.let { EncryptionMethod.parse(it) }
                        ?: EncryptionMethod.A256GCM

                Required(key, algorithm, method)
            }
    }
}

sealed interface CredentialRequest {
    val format: Format
    val unvalidatedProof: UnvalidatedProof
    val credentialResponseEncryption: RequestedResponseEncryption
}

context(Raise<String>) fun CredentialRequest.assertIsSupported(meta: CredentialConfiguration) = when (this) {
    is MsoMdocCredentialRequest -> {
        ensure(meta is MsoMdocCredentialConfiguration) { "Was expecting a ${MSO_MDOC_FORMAT.value}" }
        validate(meta)
    }

    is SdJwtVcCredentialRequest -> {
        ensure(meta is SdJwtVcCredentialConfiguration) { "Was expecting a ${SD_JWT_VC_FORMAT.value}" }
        validate(meta)
    }
}
