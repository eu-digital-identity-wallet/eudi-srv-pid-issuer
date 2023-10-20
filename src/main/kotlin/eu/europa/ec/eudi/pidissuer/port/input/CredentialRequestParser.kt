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

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.left
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jwt.JWTParser
import eu.europa.ec.eudi.pidissuer.domain.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/**
 * Tries to parse a [JsonObject] as a [CredentialRequest].
 */
fun parseCredentialRequest(request: JsonObject): Either<IssueCredentialError, CredentialRequest> =
    when (val format = (request["format"] as? JsonPrimitive)?.contentOrNull) {
        MSO_MDOC_FORMAT -> parseMsoMdocCredentialRequest(request)
        else -> IssueCredentialError.InvalidFormat(format).left()
    }

/**
 * Tries to parse a [JsonObject] as a [CredentialRequest] that contains an [MsoMdocCredentialRequest].
 */
private fun parseMsoMdocCredentialRequest(request: JsonObject): Either<IssueCredentialError, CredentialRequest> {
    /**
     * Transfer object for an MsoMdoc credential request.
     */
    @Serializable
    data class MsoMdocCredentialRequestTo(
        @Required val format: String,
        @SerialName("doctype") @Required val docType: String,
        val claims: Map<String, Map<String, JsonObject>>? = null,
        val proof: ProofTo? = null,
        @SerialName("credential_encryption_jwk") val credentialResponseEncryptionKey: JsonObject? = null,
        @SerialName("credential_response_encryption_alg") val credentialResponseEncryptionAlgorithm: String? = null,
        @SerialName("credential_response_encryption_enc") val credentialResponseEncryptionMethod: String? = null,
    )

    return either {
        fun MsoMdocCredentialRequestTo.getMsoMdocCredentialRequest() = either {
            ensure(docType.isNotBlank()) { IssueCredentialError.IssueMsoMdocCredentialError.InvalidDocType(docType) }
            MsoMdocCredentialRequest(
                docType,
                (claims ?: emptyMap()).mapValues { (_, v) -> v.map { it.key } },
            )
        }

        val credentialRequestTo = request.toDomain<MsoMdocCredentialRequestTo>().bind()
        val msoMdocCredentialRequest = credentialRequestTo.getMsoMdocCredentialRequest().bind()
        val proof = credentialRequestTo.proof?.toDomain()?.bind()
        val credentialResponseEncryption = credentialResponseEncryption(
            credentialRequestTo.credentialResponseEncryptionKey,
            credentialRequestTo.credentialResponseEncryptionAlgorithm,
            credentialRequestTo.credentialResponseEncryptionMethod,
        ).bind()
        CredentialRequest(msoMdocCredentialRequest, proof, credentialResponseEncryption)
    }
}

/**
 * Gets the [Proof] that corresponds to this [ProofTo].
 */
private fun ProofTo.toDomain(): Either<IssueCredentialError, Proof> = either {
    when (type) {
        ProofTypeTO.JWT -> {
            ensureNotNull(jwt) { IssueCredentialError.InvalidJwtProof("Missing JWT") }
            Either.catch { JWTParser.parse(jwt) }
                .map { Proof.Jwt(it) }
                .mapLeft { IssueCredentialError.InvalidJwtProof(it) }
                .bind()
        }

        ProofTypeTO.CWT -> {
            ensureNotNull(cwt) { IssueCredentialError.InvalidCwtProof("Missing CWT") }
            Proof.Cwt(cwt)
        }
    }
}

/**
 * Gets the [RequestedCredentialResponseEncryption] that corresponds to the provided values.
 */
private fun credentialResponseEncryption(
    encryptionKey: JsonObject?,
    encryptionAlgorithm: String?,
    encryptionMethod: String?,
): Either<IssueCredentialError.InvalidCredentialResponseEncryption, RequestedCredentialResponseEncryption> =
    Either.catch { encryptionKey?.let { Json.encodeToString(it) } }
        .flatMap {
            RequestedCredentialResponseEncryption(
                it,
                encryptionAlgorithm,
                encryptionMethod,
            )
        }.mapLeft { IssueCredentialError.InvalidCredentialResponseEncryption(it) }

/**
 * Tries to parse a [JsonObject] to a [T]. In case of failure an [IssueCredentialError.NonParsableCredentialRequest]
 * is returned.
 */
private inline fun <reified T> JsonObject.toDomain(): Either<IssueCredentialError.NonParsableCredentialRequest, T> =
    Either.catch { Json.decodeFromJsonElement<T>(this) }
        .mapLeft { IssueCredentialError.NonParsableCredentialRequest(it) }
