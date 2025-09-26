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
import eu.europa.ec.eudi.pidissuer.domain.Clock
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * [ServerAuthenticationEntryPoint] implementation used to commence authentication of a protected resource using DPoP.
 * Uses information from the [DPoPTokenError] to set the HTTP status code and populate the WWW-Authenticate header.
 */
class DPoPTokenServerAuthenticationEntryPoint(
    private val realm: String? = null,
    private val dpopNonce: DPoPNoncePolicy,
    private val clock: Clock,
) : ServerAuthenticationEntryPoint {

    override fun commence(exchange: ServerWebExchange, ex: AuthenticationException): Mono<Void> =
        mono {
            val details = buildList {
                if (!realm.isNullOrBlank()) {
                    add("realm" to realm)
                }
                addAll(ex.details())
            }.joinToString(separator = ", ", transform = { "${it.first}=\"${it.second}\"" })
            val wwwAuthenticate = "${AccessTokenType.DPOP.value} $details"
            val dpopNonce = ex.dpopNonce()
            exchange.response
                .apply {
                    statusCode = ex.status()
                    headers[HttpHeaders.WWW_AUTHENTICATE] = wwwAuthenticate
                    dpopNonce?.let {
                        headers["DPoP-Nonce"] = it
                    }
                }
                .setComplete()
                .awaitSingleOrNull()
        }

    /**
     * Generates a new [DPoPNonce] in case this [AuthenticationException] contains a [DPoPTokenError.UseDPoPNonce] error.
     */
    private suspend fun AuthenticationException.dpopNonce(): String? =
        when (this) {
            is OAuth2AuthenticationException ->
                when (error) {
                    is DPoPTokenError.UseDPoPNonce -> {
                        check(dpopNonce is DPoPNoncePolicy.Enforcing)
                        dpopNonce.generateDPoPNonce(clock.now())
                    }
                    else -> null
                }
            else -> null
        }
}

/**
 * Gets the details needed to construct the WWW-Authentication string that correspond to this [AuthenticationException].
 */
private fun AuthenticationException.details(): List<Pair<String, String>> =
    if (this is OAuth2AuthenticationException) {
        listOf(
            "error" to error.errorCode,
            "error_description" to error.description,
            "error_uri" to error.uri,
        ).filter { !it.second.isNullOrBlank() }
    } else {
        emptyList()
    }

/**
 * Gets the [HttpStatus] that corresponds to this [AuthenticationException].
 */
private fun AuthenticationException.status(): HttpStatus =
    when (this) {
        is OAuth2AuthenticationException ->
            when (val error = error) {
                is DPoPTokenError -> error.status
                else -> HttpStatus.UNAUTHORIZED
            }

        else -> HttpStatus.UNAUTHORIZED
    }
