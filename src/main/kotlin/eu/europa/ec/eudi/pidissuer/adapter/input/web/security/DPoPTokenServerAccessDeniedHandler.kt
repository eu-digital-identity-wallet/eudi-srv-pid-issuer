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

import com.nimbusds.oauth2.sdk.token.AccessTokenType
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * [ServerAccessDeniedHandler] implementation for DPoP.
 * Returns an insufficient scope error indicating the DPoP scheme requirement for this [realm].
 */
class DPoPTokenServerAccessDeniedHandler(
    private val realm: String? = null,
) : ServerAccessDeniedHandler {

    override fun handle(exchange: ServerWebExchange, denied: AccessDeniedException): Mono<Void> =
        mono {
            val details = buildList {
                if (!realm.isNullOrBlank()) {
                    add("realm" to realm)
                }
                add("error" to OAuth2ErrorCodes.INSUFFICIENT_SCOPE)
                add("error_description" to "The request requires higher privileges than provided by the access token.")
                add("error_uri" to "https://tools.ietf.org/html/rfc6750#section-3.1")
            }.joinToString(separator = ", ", transform = { "${it.first}=\"${it.second}\"" })
            val wwwAuthenticate = "${AccessTokenType.DPOP.value} $details"

            exchange.response
                .apply {
                    statusCode = HttpStatus.FORBIDDEN
                    headers[HttpHeaders.WWW_AUTHENTICATE] = wwwAuthenticate
                }
                .setComplete()
                .awaitSingleOrNull()
        }
}
