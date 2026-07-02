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
package eu.europa.ec.eudi.pidissuer.adapter.input.web.csrf

import kotlinx.coroutines.reactor.awaitSingleOrNull
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor
import org.springframework.security.web.server.csrf.CsrfToken
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * WebFilter used to subscribe to the CsrfToken Mono, and set it to the Exchange attribute that CsrfRequestDataValueProcessor expects.
 *
 * Based on: https://docs.spring.io/spring-security/reference/reactive/exploits/csrf.html#webflux-csrf-include
 */
class CsrfTokenSubscriberWebFilter : CoWebFilter() {
    override suspend fun filter(
        exchange: ServerWebExchange,
        chain: CoWebFilterChain,
    ) {
        val token: Mono<CsrfToken>? = exchange.getAttribute(CsrfToken::class.java.name)
        token?.awaitSingleOrNull()?.let {
            exchange.attributes[CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME] = it
        }
        chain.filter(exchange)
    }
}
