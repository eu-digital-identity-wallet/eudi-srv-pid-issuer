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

import arrow.core.NonFatal
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

/**
 * [ServerAuthenticationConverter] for [DPoPTokenAuthentication].
 */
class ServerDPoPAuthenticationTokenAuthenticationConverter : ServerAuthenticationConverter {

    override fun convert(exchange: ServerWebExchange): Mono<Authentication> =
        mono {
            try {
                val request = exchange.request
                val dpop = request.dPoP()
                val authorization = request.authorization()
                val uri = request.uri()

                if (dpop != null && authorization != null) {
                    DPoPTokenAuthentication.unauthenticated(dpop, authorization, request.method, uri)
                } else {
                    null
                }
            } catch (exception: OAuth2AuthenticationException) {
                throw exception
            } catch (exception: Exception) {
                if (NonFatal(exception))
                    throw OAuth2AuthenticationException(
                        DPoPTokenError.serverError(
                            "Unable to process DPoP request",
                            exception,
                        ),
                        exception,
                    )
                else throw exception
            }
        }
}

/**
 * Gets the value of a [header]. The header is expected to have at most 1 value. If more are found, an error is returned.
 */
private fun HttpHeaders.singleValueHeader(header: String): String? {
    val values = this[header]
    return when {
        values.isNullOrEmpty() -> null
        values.size == 1 -> values[0]
        else -> throw OAuth2AuthenticationException(DPoPTokenError.invalidRequest("Multiple '$values' header values found"))
    }
}

/**
 * Gets the DPoP header value, if any, and parses it as a [SignedJWT].
 */
private fun ServerHttpRequest.dPoP(): SignedJWT? =
    headers.singleValueHeader(AccessTokenType.DPOP.value)
        ?.takeIf { it.isNotBlank() }
        ?.let {
            try {
                SignedJWT.parse(it)
            } catch (error: Exception) {
                if (NonFatal(error))
                    throw OAuth2AuthenticationException(
                        DPoPTokenError.invalidRequest("'${AccessTokenType.DPOP.value}' header is not a valid signed JWT"),
                    )
                else throw error
            }
        }

/**
 * Gets the Authorization header value, if any.
 */
private fun ServerHttpRequest.authorization(): DPoPAccessToken? =
    headers.singleValueHeader(HttpHeaders.AUTHORIZATION)
        ?.takeIf { it.isNotBlank() && it.startsWith(AccessTokenType.DPOP.value) }
        ?.let {
            try {
                DPoPAccessToken.parse(it)
            } catch (error: Exception) {
                if (NonFatal(error))
                    throw OAuth2AuthenticationException(
                        DPoPTokenError.invalidRequest("'${HttpHeaders.AUTHORIZATION}' header is not a valid DPoP access token"),
                    )
                else throw error
            }
        }

/**
 * Gets the uri of the current [ServerHttpRequest]. The uri does not contain query parameters or fragments.
 */
private fun ServerHttpRequest.uri(): URI = URI.create(UriComponentsBuilder.fromUri(uri).query(null).fragment(null).toUriString())
