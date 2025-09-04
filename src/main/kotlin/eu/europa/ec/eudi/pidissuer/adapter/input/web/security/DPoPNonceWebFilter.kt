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
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.time.Clock

/**
 * [WebFilter] that generates a new DPoP Nonce for DPoP authenticated web requests and explicitly configured paths.
 */
class DPoPNonceWebFilter(
    private val dpopNonce: DPoPNoncePolicy.Enforcing,
    private val clock: Clock,
    private val paths: List<String>,
) : WebFilter {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> =
        mono {
            val request = exchange.request
            if (request.requiresDPoPNonce()) {
                val newDPoPNonce = dpopNonce.generateDPoPNonce(clock.instant())
                val response = exchange.response
                response.headers["DPoP-Nonce"] = newDPoPNonce
            }
            chain.filter(exchange).awaitSingleOrNull()
        }

    private suspend fun ServerHttpRequest.requiresDPoPNonce(): Boolean {
        val isUsingDPoP = ReactiveSecurityContextHolder.getContext().awaitSingleOrNull()?.authentication is DPoPTokenAuthentication
        val isExplicitlyConfigured = path.pathWithinApplication().value() in paths
        return isUsingDPoP || isExplicitlyConfigured
    }
}
