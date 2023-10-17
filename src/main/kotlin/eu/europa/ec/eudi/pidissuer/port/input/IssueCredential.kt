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
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.result
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.MsmMdocCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.pid.Pid
import eu.europa.ec.eudi.pidissuer.domain.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.validate
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
enum class ProofTypeTO {
    @SerialName(
        "jwt",
    )
    JWT,

    @SerialName(
        "cwt",
    )
    CWT,
}

@Serializable
data class ProofTo(
    @SerialName("proof_type") val type: ProofTypeTO,
    val jwt: String? = null,
    val cwt: String? = null,
)

// Fields for MSO MDOC profile

typealias MsoMdocClaimsTO = JsonObject

@Serializable
class CredentialRequestTO(
    val format: String,
    val proof: ProofTo? = null,
    // @SerialName("credential_encryption_jwk") val credentialEncryptionJwk: JWK? = null,
    @SerialName("doctype") val msoMdocDoctype: String? = null,

)

class IssueCredential(
    private val getPidData: GetPidData,
) {
    suspend operator fun invoke(accessToken: String, request: JsonObject): Result<Pid> = result {
        getPidData(accessToken) ?: error("Cannot map PID")
    }

    fun validateForPidMsoMdoc(credentialRequest: CredentialRequest): Either<String, Unit> = either {
        val format = credentialRequest.format
        ensure(format is MsmMdocCredentialRequest) { "Not related to MsoMdoc" }
        format.validate(PidMsoMdocV1).bind()
    }
}
