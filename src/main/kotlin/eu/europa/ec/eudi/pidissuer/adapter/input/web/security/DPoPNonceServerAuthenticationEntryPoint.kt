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
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * [HttpStatusServerEntryPoint] subclass that can reply with 'use_dpop_nonce' errors whenever DPoP authentication fails
 * due to Nonce errors.
 */
class DPoPNonceServerAuthenticationEntryPoint(
    private val realm: String? = null,
    private val generateDPoPNonce: GenerateDPoPNonce,
) : HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED) {

    override fun commence(exchange: ServerWebExchange, authException: AuthenticationException): Mono<Void> =
        mono {
            if (authException !is OAuth2AuthenticationException) {
                super.commence(exchange, authException).awaitSingleOrNull()
            } else {
                val error = authException.error
                if (error !is DPoPTokenError ||
                    error.errorCode != OAuth2ErrorCodes.INVALID_TOKEN ||
                    error.jwkThumbprint == null ||
                    !error.description.contains("nonce", ignoreCase = true)
                ) {
                    super.commence(exchange, authException).awaitSingleOrNull()
                } else {
                    val details = buildMap {
                        if (!realm.isNullOrBlank()) {
                            put("realm", realm)
                        }
                        put("error", "use_dpop_nonce")
                        put("error_description", authException.error.description)
                    }.entries.joinToString(separator = ", ", transform = { "${it.key}=\"${it.value}\"" })
                    val dpopNonce = generateDPoPNonce(error.jwkThumbprint)
                    val wwwAuthenticate = "${AccessTokenType.DPOP.value} $details"

                    exchange.response
                        .apply {
                            statusCode = error.status
                            headers[HttpHeaders.WWW_AUTHENTICATE] = wwwAuthenticate
                            headers["DPoP-Nonce"] = dpopNonce.nonce.value
                        }
                        .setComplete()
                        .awaitSingleOrNull()
                }
            }
        }
}
