/*
 * Copyright (c) 2023-2026 European Commission
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
package eu.europa.ec.eudi.pidissuer.adapter.out.status

import arrow.core.raise.catch
import arrow.core.raise.context.Raise
import arrow.core.raise.context.raise
import com.eygraber.uri.Uri
import com.eygraber.uri.Url
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.domain.toZonedDateTime
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import kotlinx.datetime.TimeZone
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.http.MediaType
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import org.springframework.web.reactive.function.client.awaitExchange
import java.time.format.DateTimeFormatter
import kotlin.time.Instant

class GenerateStatusListTokenWithExternalService(
    private val webClient: WebClient,
    private val serviceUrl: Url,
    private val apiKey: String,
    private val timeZone: TimeZone,
) : AllocateStatus {
    context(_: Raise<AllocateStatus.Error>)
    override suspend fun invoke(
        type: String,
        expiration: Instant,
    ): StatusListToken = catch({ allocateStatus(type, expiration) }) { raise(AllocateStatus.Error(type, it)) }

    private suspend fun allocateStatus(
        type: String,
        expiration: Instant,
    ): StatusListToken {
        require(type.isNotBlank()) { "type cannot be blank" }

        val statusTokens =
            webClient
                .post()
                .uri(serviceUrl.toString())
                .headers {
                    it.contentType = MediaType.APPLICATION_FORM_URLENCODED
                    it.accept = listOf(MediaType.APPLICATION_JSON)
                    it.set("X-API-Key", apiKey)
                }.body(
                    BodyInserters.fromFormData(
                        LinkedMultiValueMap<String, String>().apply {
                            add("country", "FC")
                            add("doctype", type)
                            add(
                                "expiry_date",
                                expiration.toZonedDateTime(timeZone).format(DateTimeFormatter.ISO_LOCAL_DATE),
                            )
                        },
                    ),
                ).awaitExchange { it.awaitBody<StatusTokensTO>() }

        return StatusListToken(
            statusList = statusTokens.statusListToken.statusList,
            index = statusTokens.statusListToken.index,
        )
    }
}

@Serializable
private data class StatusTokensTO(
    @Required @SerialName("status_list") val statusListToken: StatusListTokenTO,
)

@Serializable
private data class StatusListTokenTO(
    @Required @SerialName("idx") val index: UInt,
    @Required @SerialName("uri") val statusList: Uri,
)
