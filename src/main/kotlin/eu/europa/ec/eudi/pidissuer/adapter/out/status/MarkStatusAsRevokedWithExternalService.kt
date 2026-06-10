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

import arrow.core.Either
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.status.MarkStatusAsRevoked
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitExchange
import java.net.URL

internal class MarkStatusAsRevokedWithExternalService(
    private val webClient: WebClient,
    private val serviceUrl: URL,
    private val apiKey: String,
) : MarkStatusAsRevoked {
    override suspend fun invoke(status: StatusListToken) =
        webClient.post()
            .uri(serviceUrl.toExternalForm())
            .headers {
                it.set(API_KEY_HEADER, apiKey)
            }
            .body(
                BodyInserters.fromFormData(
                    LinkedMultiValueMap<String, String>().apply {
                        add(IDX_PARAM, status.index.toString())
                        add(URI_PARAM, status.statusList.toString())
                        add(STATUS_PARAM, STATUS_REVOKED)
                    },
                ),
            )
            .awaitExchange { response ->
                Either.catch {
                    check(response.statusCode().is2xxSuccessful) {
                        "Revocation service responded with ${response.statusCode()}"
                    }
                }
            }

    companion object {
        private const val API_KEY_HEADER = "X-API-Key"
        private const val IDX_PARAM = "idx"
        private const val URI_PARAM = "uri"
        private const val STATUS_PARAM = "status"
        private const val STATUS_REVOKED = "1"
    }
}
