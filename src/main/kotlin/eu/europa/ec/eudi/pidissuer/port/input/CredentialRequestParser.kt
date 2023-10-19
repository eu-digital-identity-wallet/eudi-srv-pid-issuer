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
import arrow.core.left
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.raise.withError
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import eu.europa.ec.eudi.pidissuer.domain.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

private typealias ClaimsTo = Map<String, Map<String, JsonObject>>

fun parseCredentialRequest(request: JsonObject): Either<IssueCredentialError, CredentialRequest> =
    when (val format = (request["format"] as? JsonPrimitive)?.contentOrNull) {
        MSO_MDOC_FORMAT -> parseMsoMdocCredentialRequest(request)
        else -> IssueCredentialError.InvalidFormat(format).left()
    }

private fun parseMsoMdocCredentialRequest(request: JsonObject): Either<IssueCredentialError, CredentialRequest> {
    /**
     * Transfer object for an MsoMdoc credential request.
     */
    @Serializable
    data class MsoMdocCredentialRequestTo(
        @Required val format: String,
        @SerialName("doctype") @Required val docType: String,
        val claims: ClaimsTo? = null,
        val proof: ProofTo? = null,
        @SerialName("credential_encryption_jwk") val credentialResponseEncryptionKey: JsonObject? = null,
        @SerialName("credential_response_encryption_alg") val credentialResponseEncryptionAlgorithm: String? = null,
        @SerialName("credential_response_encryption_enc") val credentialResponseEncryptionMethod: String? = null,
    )

    return either {
        fun MsoMdocCredentialRequestTo.getMsoMdocCredentialRequest(): MsoMdocCredentialRequest = error {
            MsoMdocCredentialRequest(
                ensureNotNull(docType) { IssueCredentialError.IssueMsoMdocCredentialError.InvalidDocType(docType) },
                (claims ?: emptyMap()).mapValues { (_, v) -> v.map { it.key } },
            )
        }

        val credentialRequestTo = request.toDomain<MsoMdocCredentialRequestTo>().bind()
        val msoMdocCredentialRequest = credentialRequestTo.getMsoMdocCredentialRequest()
        val proof = credentialRequestTo.proof?.toDomain()
        val credentialResponseEncryption = credentialResponseEncryption(
            credentialRequestTo.credentialResponseEncryptionKey,
            credentialRequestTo.credentialResponseEncryptionAlgorithm,
            credentialRequestTo.credentialResponseEncryptionMethod,
        )
        CredentialRequest(msoMdocCredentialRequest, proof, credentialResponseEncryption)
    }
}

/**
 * Gets the [Proof] that corresponds to this [MsoMdocCredentialRequestTo].
 * In case of an error an [IssueCredentialError] is raised in the current [Raise] context.
 */
context(Raise<IssueCredentialError>)
fun ProofTo.toDomain(): Proof = either {
    when (type) {
        ProofTypeTO.JWT -> {
            ensureNotNull(jwt) { IssueCredentialError.InvalidJwtProof("Missing JWT") }
            withError<IssueCredentialError, Throwable, Proof>({ t -> IssueCredentialError.InvalidJwtProof(t) }) {
                val signedJwt: JWT = Either.catch { JWTParser.parse(jwt) }.bind()
                Proof.Jwt(signedJwt)
            }
        }

        ProofTypeTO.CWT -> {
            ensureNotNull(cwt) { IssueCredentialError.InvalidCwtProof("Missing CWT") }
            Proof.Cwt(cwt)
        }
    }
}.bind()

/**
 * Gets the [RequestedCredentialResponseEncryption] that corresponds to this [MsoMdocCredentialRequestTo].
 * In case of an error an [IssueMsoMdocCredentialError] is raised in the current [Raise] context.
 */
context(Raise<IssueCredentialError.InvalidCredentialResponseEncryption>)
private fun credentialResponseEncryption(
    encryptionKey: JsonObject?,
    encryptionAlgorithm: String?,
    encryptionMethod: String?,
): RequestedCredentialResponseEncryption =
    withError({ t -> IssueCredentialError.InvalidCredentialResponseEncryption(t) }) {
        RequestedCredentialResponseEncryption(
            encryptionKey?.let { Json.encodeToString(it) },
            encryptionAlgorithm,
            encryptionMethod,
        ).bind()
    }

/**
 * Tries to parse a [JsonObject] to a [MsoMdocCredentialRequestTo]. In case of failure
 * an [IssueCredentialError.NonParsableCredentialRequest] error is raised in the current [Raise] context.
 */
private inline fun <reified T> JsonObject.toDomain(): Either<IssueCredentialError.NonParsableCredentialRequest, T> =
    Either.catch { Json.decodeFromJsonElement<T>(this) }
        .mapLeft { IssueCredentialError.NonParsableCredentialRequest(it) }
