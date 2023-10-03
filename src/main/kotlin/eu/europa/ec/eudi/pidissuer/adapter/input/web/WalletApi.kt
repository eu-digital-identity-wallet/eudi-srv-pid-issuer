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
import kotlinx.coroutines.reactor.awaitSingle
import org.springframework.http.MediaType
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal
import org.springframework.web.reactive.function.server.*

class WalletApi(private val issueCredential: IssueCredential) {

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
        val principal: OAuth2IntrospectionAuthenticatedPrincipal = req
            .principal()
            .awaitSingle()
            .run {
                require(this is BearerTokenAuthentication)
                require(principal is OAuth2IntrospectionAuthenticatedPrincipal)
                principal as OAuth2IntrospectionAuthenticatedPrincipal
            }

        return ServerResponse.ok().json().bodyValueAndAwait(principal.claims)
    }
    companion object {
        const val CREDENTIAL_ENDPOINT = "/wallet/credentialEndpoint"
    }
}
