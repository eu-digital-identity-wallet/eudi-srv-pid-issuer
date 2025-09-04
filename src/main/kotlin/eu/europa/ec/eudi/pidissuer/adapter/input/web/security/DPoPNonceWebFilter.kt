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
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange

/**
 * [CoWebFilter] that checks if new DPoP Nonce values must be generated for DPoP authenticated web requests.
 */
class DPoPNonceWebFilter(
    private val dpopNonce: DPoPNoncePolicy.Enforcing,
) : CoWebFilter() {
    override suspend fun filter(
        exchange: ServerWebExchange,
        chain: CoWebFilterChain,
    ) {
        val request = exchange.request
        if (request.headers.contains("DPoP")) {
            val authentication = ReactiveSecurityContextHolder.getContext()
                .awaitSingleOrNull()
                ?.authentication

            if (authentication is DPoPTokenAuthentication) {
                val newDPoPNonce = dpopNonce.generateDPoPNonce()
                val response = exchange.response
                response.headers["DPoP-Nonce"] = newDPoPNonce.nonce.value
            }
        }

        chain.filter(exchange)
    }
}
