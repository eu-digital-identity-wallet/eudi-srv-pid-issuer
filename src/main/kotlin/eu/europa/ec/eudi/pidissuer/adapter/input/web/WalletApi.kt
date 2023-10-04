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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import eu.europa.ec.eudi.pidissuer.port.input.IssueCredential
import kotlinx.serialization.json.JsonObject
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import org.springframework.web.reactive.function.server.*
import java.net.URL

class WalletApi(
    private val issueCredential: IssueCredential,
    private val authorizationServerUserInfoEndPoint: URL,
) {

    val route = coRouter {
        POST(
            CREDENTIAL_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            this@WalletApi::handleIssueCredential,
        )
        GET(
            CREDENTIAL_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            this@WalletApi::helloHolder,

        )
    }

    private suspend fun handleIssueCredential(req: ServerRequest): ServerResponse {
        TODO()
    }

    private suspend fun helloHolder(req: ServerRequest): ServerResponse {
        val webClient: WebClient = WebClient.create(authorizationServerUserInfoEndPoint.toString())
        val userInfo = webClient.get().accept(MediaType.APPLICATION_JSON)
            .header("Authorization", req.headers().header("Authorization")[0])
            .retrieve()
            .awaitBody<JsonObject>()

        return ServerResponse.ok().json().bodyValueAndAwait(userInfo)
    }
    companion object {
        const val CREDENTIAL_ENDPOINT = "/wallet/credentialEndpoint"
    }
}
