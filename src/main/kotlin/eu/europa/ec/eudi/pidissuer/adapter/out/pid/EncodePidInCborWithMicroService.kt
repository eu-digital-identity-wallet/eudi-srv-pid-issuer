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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.io.StringWriter
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

private val log = LoggerFactory.getLogger(EncodePidInCborWithMicroService::class.java)

class EncodePidInCborWithMicroService(
    private val creatorUrl: HttpsUrl,
    private val webClient: WebClient,
) : EncodePidInCbor {

    init {
        log.info("Initialized using: $creatorUrl")
    }

    override suspend fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: ECKey,
    ): String = coroutineScope {
        log.info("Requesting PID in mso_mdoc for ${pid.familyName} ...")
        val request = createMsoMdocReq(pid, pidMetaData, holderKey)
        val response = webClient
            .post()
            .uri(creatorUrl.externalForm)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .retrieve()
            .awaitBody<CreateMsoMdocResponse>()
        response.fold().getOrThrow()
    }
}

@OptIn(ExperimentalEncodingApi::class)
fun ECKey.base64EncodedPem(): String {
    val output = StringWriter()
    PemWriter(output).use { pemWriter ->
        val pem = PemObject("PUBLIC KEY", this.toECPublicKey().encoded)
        pemWriter.writeObject(pem)
    }
    val pem = output.toString()
    return Base64.UrlSafe.encode(pem.toByteArray())
}

internal fun createMsoMdocReq(
    pid: Pid,
    pidMetaData: PidMetaData,
    key: ECKey,
): JsonObject =
    buildJsonObject {
        put("version", "0.3")
        put("country", "FC")
        put("doctype", PidMsoMdocV1.docType)
        put("device_publickey", key.base64EncodedPem())
        putJsonObject("data") {
            val nameSpaces = PidMsoMdocV1.msoClaims.keys
            check(nameSpaces.isNotEmpty())
            val defaultNameSpace = nameSpaces.iterator().next()
            putJsonObject(defaultNameSpace) {
                put("given_name", pid.givenName.value)
                put("family_name", pid.familyName.value)
                put("birth_date", pid.birthDate.toString())
                pid.familyNameBirth?.let { put("birth_family_name", it.value) }
                pid.givenNameBirth?.let { put("birth_given_name", it.value) }
                pid.gender?.let { put("gender", it.value.toInt()) }
                pid.nationality?.let { put("nationalities", JsonArray(listOf(JsonPrimitive(it.value)))) }
                put("is_over_18", pid.ageOver18)
                pid.ageBirthYear?.let { put("age_birth_year", it.value) }
                put("unique_id", pid.uniqueId.value)
                put("issuance_date", pidMetaData.issuanceDate.toString())
                put("expiry_date", pidMetaData.expiryDate.toString())
                when (val issuingAuthority = pidMetaData.issuingAuthority) {
                    is IssuingAuthority.MemberState -> put("issuing_authority", issuingAuthority.code.value)
                    is IssuingAuthority.AdministrativeAuthority -> put("issuing_authority", issuingAuthority.value)
                }
                put("issuing_country", pidMetaData.issuingCountry.value)
            }
        }
    }

@Serializable
private data class CreateMsoMdocResponse(
    @SerialName("error_code") val errorCode: Int? = null,
    @SerialName("error_message") val errorMessage: String? = null,
    @SerialName("mdoc") val mdoc: String? = null,
)

private fun CreateMsoMdocResponse.fold(): Result<String> =
    when {
        !mdoc.isNullOrBlank() -> Result.success(mdoc)
        else -> Result.failure(RuntimeException("Failed to issue mso_mdoc. ErrorCode = $errorCode, ErrorMessage = $errorMessage"))
    }
