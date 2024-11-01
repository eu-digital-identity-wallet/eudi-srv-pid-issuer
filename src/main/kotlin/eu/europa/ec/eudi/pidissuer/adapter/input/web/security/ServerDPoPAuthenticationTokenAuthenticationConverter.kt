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

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
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

    override fun convert(exchange: ServerWebExchange): Mono<Authentication> {
        val request = exchange.request
        val dpop = request.dPoP()
        val authorization = request.authorization()
        val method = request.method
        val uri = request.uri()

        return Mono.zip(dpop, authorization, uri)
            .onErrorMap {
                when (it) {
                    is OAuth2AuthenticationException -> it
                    else -> {
                        val error = DPoPTokenError.serverError("Unable to process DPoP request")
                        OAuth2AuthenticationException(error, it)
                    }
                }
            }
            .map { DPoPTokenAuthentication.unauthenticated(it.t1, it.t2, method, it.t3) }
    }
}

/**
 * Gets the value of a [header]. The header is expected to have at most 1 value. If more are found, an error is returned.
 */
private fun HttpHeaders.singleValueHeader(header: String): Mono<String> {
    val values = this[header]
    return when {
        values.isNullOrEmpty() -> Mono.empty()
        values.size == 1 -> Mono.justOrEmpty(values[0])
        else -> {
            val error = DPoPTokenError.invalidRequest("Multiple '$values' header values found")
            Mono.error(OAuth2AuthenticationException(error))
        }
    }
}

/**
 * Gets the DPoP header value, if any, and parses it as a [SignedJWT].
 */
private fun ServerHttpRequest.dPoP(): Mono<SignedJWT> = headers.singleValueHeader(AccessTokenType.DPOP.value)
    .filter { !it.isNullOrBlank() }
    .flatMap {
        Mono.fromCallable { SignedJWT.parse(it) }
            .onErrorMap {
                val error =
                    DPoPTokenError.invalidRequest("'${AccessTokenType.DPOP.value}' header is not a valid signed JWT")
                OAuth2AuthenticationException(error)
            }
    }

/**
 * Gets the Authorization header value, if any.
 */
private fun ServerHttpRequest.authorization(): Mono<DPoPAccessToken> = headers.singleValueHeader(HttpHeaders.AUTHORIZATION)
    .filter { !it.isNullOrBlank() && it.startsWith(AccessTokenType.DPOP.value) }
    .flatMap {
        Mono.fromCallable { DPoPAccessToken.parse(it) }
            .onErrorMap {
                val error =
                    DPoPTokenError.invalidRequest("'${HttpHeaders.AUTHORIZATION}' header is not a valid DPoP access token")
                OAuth2AuthenticationException(error)
            }
    }

/**
 * Gets the uri of the current [ServerHttpRequest]. The uri does not contain query parameters or fragments.
 */
private fun ServerHttpRequest.uri(): Mono<URI> = Mono.fromCallable {
    val uri = UriComponentsBuilder.fromUri(uri).query(null).fragment(null).toUriString()
    URI.create(uri)
}
