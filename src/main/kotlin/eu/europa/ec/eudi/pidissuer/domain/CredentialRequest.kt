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
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWT
import kotlinx.serialization.json.JsonObject

/**
 * Proof of possession.
 */
sealed interface Proof {

    /**
     * Proof of possession using a JWT.
     */
    data class Jwt(val jwt: JWT) : Proof

    /**
     * Proof of possession using a CWT.
     */
    data class Cwt(val cwt: String) : Proof
}

sealed interface RequestedCredentialResponseEncryption {

    /**
     */
    data object NotRequired : RequestedCredentialResponseEncryption

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
    ) : RequestedCredentialResponseEncryption

    companion object {
        operator fun invoke(
            encryptionKey: String?,
            encryptionAlgorithm: String?,
            encryptionMethod: String?,
        ): Either<Throwable, RequestedCredentialResponseEncryption> = either {
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

sealed interface CredentialRequestFormat

data class CredentialRequest(
    val format: CredentialRequestFormat,
    val proof: Proof? = null,
    val credentialResponseEncryption: RequestedCredentialResponseEncryption = RequestedCredentialResponseEncryption.NotRequired,
)

fun CredentialRequest.validate(meta: CredentialMetaData): Either<String, Unit> = either {
    when (format) {
        is MsoMdocCredentialRequestFormat -> {
            ensure(meta is MsoMdocMetaData) { "Wrong metadata" }
            format.validate(meta).bind()
        }

        is SdJwtVcCredentialRequest -> {
            ensure(meta is SdJwtVcMetaData) { "Wrong metadata" }
            format.validate(meta)
        }
    }
}

sealed interface IssuedCredential {
    data class Jwt(val jwt: JWT): IssuedCredential
    data class Json(val jsonObject: JsonObject): IssuedCredential
}


