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
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialRequest
import eu.europa.ec.eudi.pidissuer.port.input.IssueMsoMdocCredentialError.InvalidDocType
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * The format of an MsoMdoc credential request.
 */
internal const val MsoMdocFormat = "mso_mdoc"

private typealias ClaimsTo = Map<String, Map<String, JsonObject>>

/**
 * Transfer object for an MsoMdoc credential request.
 */
@Serializable
private data class MsoMdocCredentialRequestTo(
    @Required val format: String,
    @SerialName("doctype") @Required val docType: String,
    val claims: ClaimsTo? = null,
    val proof: ProofTo? = null,
    @SerialName("credential_encryption_jwk") val credentialResponseEncryptionKey: JsonObject? = null,
    @SerialName("credential_response_encryption_alg") val credentialResponseEncryptionAlgorithm: String? = null,
    @SerialName("credential_response_encryption_enc") val credentialResponseEncryptionMethod: String? = null,
)

/**
 * Errors that can occur while trying to issue an MsoMdoc credential.
 */
sealed interface IssueMsoMdocCredentialError : IssueCredentialError {

    /**
     * Indicates a credential request contained an invalid 'docType'.
     */
    data class InvalidDocType(val docType: String) : IssueMsoMdocCredentialError
}

/**
 * The result of trying to issue an MsoMdoc credential.
 */
internal typealias IssueMsoMdocCredentialResult = Either<IssueCredentialError, String>

/**
 * Service for issuing MsoMdoc credentials.
 */
internal class IssueMsoMdocCredential(private val getPidData: GetPidData) {

    internal suspend operator fun invoke(accessToken: String, request: JsonObject): IssueMsoMdocCredentialResult =
        either {
            val credentialRequestTo = request.toDomain<MsoMdocCredentialRequestTo>().bind()
            val msoMdocCredentialRequest = credentialRequestTo.getMsoMdocCredentialRequest()
            val proof = credentialRequestTo.proof?.toDomain()
            val credentialResponseEncryption = credentialResponseEncryption(
                credentialRequestTo.credentialResponseEncryptionKey,
                credentialRequestTo.credentialResponseEncryptionAlgorithm,
                credentialRequestTo.credentialResponseEncryptionMethod,
            )

            val credentialRequest = CredentialRequest(msoMdocCredentialRequest, proof, credentialResponseEncryption)
            TODO()
        }
}

/**
 * Gets the [MsoMdocCredentialRequest] that corresponds to this [MsoMdocCredentialRequestTo].
 * In case of an error an [IssueMsoMdocCredentialError] is raised in the current [Raise] context.
 */
context(Raise<IssueMsoMdocCredentialError>)
private fun MsoMdocCredentialRequestTo.getMsoMdocCredentialRequest(): MsoMdocCredentialRequest = error {
    MsoMdocCredentialRequest(
        ensureNotNull(docType) { InvalidDocType(docType) },
        (claims ?: emptyMap()).mapValues { (_, v) -> v.map { it.key } },
    )
}
