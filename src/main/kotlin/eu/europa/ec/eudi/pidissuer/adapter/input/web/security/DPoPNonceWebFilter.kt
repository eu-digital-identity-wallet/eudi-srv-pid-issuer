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
package eu.europa.ec.eudi.pidissuer.adapter.input.web.security

import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * [WebFilter] that checks if new DPoP Nonce values must be generated for DPoP authenticated web requests.
 */
class DPoPNonceWebFilter(
    private val loadActiveDPoPNonce: LoadActiveDPoPNonce,
    private val generateDPoPNonce: GenerateDPoPNonce,
) : WebFilter {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> =
        mono {
            val request = exchange.request
            if (request.headers.contains("DPoP")) {
                val authentication = ReactiveSecurityContextHolder.getContext()
                    .awaitSingleOrNull()
                    ?.authentication

                if (authentication is DPoPTokenAuthentication && authentication.jwkThumbprint != null) {
                    val currentDPoPNonce = loadActiveDPoPNonce(authentication.jwkThumbprint)
                    if (currentDPoPNonce == null) {
                        val newDPoPNonce = generateDPoPNonce(authentication.jwkThumbprint)
                        val response = exchange.response
                        response.headers["DPoP-Nonce"] = newDPoPNonce.nonce.value
                    }
                }
            }

            chain.filter(exchange).awaitSingleOrNull()
        }
}
