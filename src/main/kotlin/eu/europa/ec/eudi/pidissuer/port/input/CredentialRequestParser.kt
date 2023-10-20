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
import arrow.core.raise.*
import com.nimbusds.jwt.JWTParser
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.CredentialRequestTO.MsoMdoc
import eu.europa.ec.eudi.pidissuer.port.input.CredentialRequestTO.SdJwtVc
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidCredentialResponseEncryption
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.SdJwtVcError
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/**
 * Tries to parse a [JsonObject] as a [CredentialRequest].
 */
fun CredentialRequestTO.toDomain(): Either<IssueCredentialError, CredentialRequest> = either {

    val proof = proof?.toDomain()?.bind()
    val credentialResponseEncryption = credentialResponseEncryption.toDomain().bind()
    val credentialRequestFormat: CredentialRequestFormat = when (this@toDomain) {
        is MsoMdoc -> parseMsoMdocCredentialRequest(this@toDomain)
        is SdJwtVc -> credentialDefinition.toDomain()
    }.bind()
    CredentialRequest(credentialRequestFormat, proof, credentialResponseEncryption)
}


/**
 * Tries to parse a [JsonObject] as a [CredentialRequest] that contains an [MsoMdocCredentialRequestFormat].
 */
private fun parseMsoMdocCredentialRequest(credentialRequestTo: MsoMdoc): Either<IssueCredentialError, MsoMdocCredentialRequestFormat> =
    either {
        fun MsoMdoc.getMsoMdocCredentialRequest() = either {
            ensure(docType.isNotBlank()) { IssueCredentialError.IssueMsoMdocCredentialError.InvalidDocType(docType) }
            MsoMdocCredentialRequestFormat(
                docType,
                (claims ?: emptyMap()).mapValues { (_, v) -> v.map { it.key } },
            )
        }
        credentialRequestTo.getMsoMdocCredentialRequest().bind()
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


private fun SdJwtVcCredentialDefinition.toDomain(): Either<SdJwtVcError.UnsupportedType, SdJwtVcCredentialRequest> =
    either {
        ensure(type.isNotBlank()) { SdJwtVcError.UnsupportedType(type) }
        SdJwtVcCredentialRequest(SdJwtVcType(type), emptyList())
    }

/**
 * Gets the [RequestedCredentialResponseEncryption] that corresponds to the provided values.
 */
private fun CredentialResponseEncryptionTO.toDomain(): Either<InvalidCredentialResponseEncryption, RequestedCredentialResponseEncryption> =
    either {
        withError({ t: Throwable -> InvalidCredentialResponseEncryption(t) }) {
            val encryptionKey = credentialResponseEncryptionKey?.let { Json.encodeToString(it) }
            RequestedCredentialResponseEncryption(
                encryptionKey,
                credentialResponseEncryptionAlgorithm,
                credentialResponseEncryptionMethod,
            ).bind()
        }
    }

/**
 * Tries to parse a [JsonObject] to a [T]. In case of failure an [IssueCredentialError.NonParsableCredentialRequest]
 * is returned.
 */
private inline fun <reified T> JsonObject.toTO(): Either<IssueCredentialError.NonParsableCredentialRequest, T> =
    either {
        catch({ Json.decodeFromJsonElement<T>(this@toTO) }) { t: Throwable ->
            raise(IssueCredentialError.NonParsableCredentialRequest(t))
        }
    }

