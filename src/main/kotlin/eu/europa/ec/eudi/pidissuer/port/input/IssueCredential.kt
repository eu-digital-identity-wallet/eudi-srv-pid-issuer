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
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

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

/**
 * Errors that might be raised while trying to issue a credential.
 */
sealed interface IssueCredentialError {

    /**
     * Indicates the requested credential format is not invalid.
     */
    data class InvalidCredentialFormat(val format: String?) : IssueCredentialError
}

class IssueCredential(getPidData: GetPidData) {

    private val issueMsoMdocCredential = IssueMsoMdocCredential(getPidData)

    suspend operator fun invoke(accessToken: String, request: JsonObject): Either<IssueCredentialError, String> =
        when (val format = (request["format"] as? JsonPrimitive)?.contentOrNull) {
            MsoMdocFormat -> issueMsoMdocCredential(accessToken, request)
            else -> IssueCredentialError.InvalidCredentialFormat(format).left()
        }
}
