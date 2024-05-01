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
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.toBase64UrlSafeEncodedPem
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody

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
        webClient.post()
            .uri(creatorUrl.externalForm)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .retrieve()
            .awaitBody<CreateMsoMdocResponse>()
            .fold()
            .getOrThrow()
    }
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
        put("device_publickey", key.toBase64UrlSafeEncodedPem())
        putJsonObject("data") {
            val nameSpaces = PidMsoMdocV1.msoClaims.keys
            check(nameSpaces.isNotEmpty())
            val defaultNameSpace = nameSpaces.iterator().next()
            putJsonObject(defaultNameSpace) {
                put(GivenNameAttribute.name, pid.givenName.value)
                put(FamilyNameAttribute.name, pid.familyName.value)
                put(BirthDateAttribute.name, pid.birthDate.toString())
                pid.familyNameBirth?.let { put(FamilyNameBirthAttribute.name, it.value) }
                pid.givenNameBirth?.let { put(GivenNameBirthAttribute.name, it.value) }
                pid.gender?.let { put(GenderAttribute.name, it.value.toInt()) }
                pid.nationality?.let { put(NationalityAttribute.name, it.value) }
                pid.ageOver18?.let { put(AgeOver18Attribute.name, it) }
                pid.ageBirthYear?.let { put(AgeBirthYearAttribute.name, it.value) }
                pid.ageInYears?.let { put(AgeInYearsAttribute.name, it.toInt()) }
                pid.birthPlace?.let { put(BirthPlaceAttribute.name, it) }
                pid.birthCountry?.let { put(BirthCountryAttribute.name, it.value) }
                pid.birthState?.let { put(BirthStateAttribute.name, it.value) }
                pid.birthCity?.let { put(BirthCountryAttribute.name, it.value) }
                pid.residentAddress?.let { put(ResidenceAddress.name, it) }
                pid.residentCountry?.let { put(ResidenceCountryAttribute.name, it.value) }
                pid.residentState?.let { put(ResidenceStateAttribute.name, it.value) }
                pid.residentCity?.let { put(ResidenceCityAttribute.name, it.value) }
                pid.residentPostalCode?.let { put(ResidencePostalCodeAttribute.name, it.value) }
                pid.residentStreet?.let { put(ResidenceStreetAttribute.name, it.value) }
                pid.residentHouseNumber?.let { put(ResidenceHouseNumberAttribute.name, it) }

                put(IssuanceDateAttribute.name, pidMetaData.issuanceDate.toString())
                put(ExpiryDateAttribute.name, pidMetaData.expiryDate.toString())
                when (val issuingAuthority = pidMetaData.issuingAuthority) {
                    is IssuingAuthority.MemberState -> put(IssuanceDateAttribute.name, issuingAuthority.code.value)
                    is IssuingAuthority.AdministrativeAuthority -> put(
                        IssuanceDateAttribute.name,
                        issuingAuthority.value,
                    )
                }
                pidMetaData.documentNumber?.let { put(DocumentNumberAttribute.name, it.value) }
                pidMetaData.administrativeNumber?.let { put(AdministrativeNumberAttribute.name, it.value) }
                put(IssuingCountryAttribute.name, pidMetaData.issuingCountry.value)
                pidMetaData.issuingJurisdiction?.let { put(IssuingJurisdictionAttribute.name, it) }
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
