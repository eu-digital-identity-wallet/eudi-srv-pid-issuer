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

import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils
import net.minidev.json.JSONObject
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

/**
 * [ReactiveAuthenticationManager] implementing DPoP authentication.
 * Implementation information can be found
 * [here](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/examples/oauth/dpop#rs).
 */
class DPoPTokenReactiveAuthenticationManager(
    private val introspector: SpringReactiveOpaqueTokenIntrospector,
    private val verifier: DPoPProtectedResourceRequestVerifier,
) : ReactiveAuthenticationManager {

    /**
     * Performs DPoP authentication.
     */
    override fun authenticate(authentication: Authentication): Mono<Authentication> =
        Mono.just(authentication)
            .filter { it is DPoPTokenAuthentication }
            .map { it as DPoPTokenAuthentication }
            .flatMap { dPoPAuthentication ->
                introspect(dPoPAuthentication.accessToken)
                    .flatMap { principal ->
                        val issuer = principal.issuer()
                        val thumbprint = principal.jwkThumbprint()
                        Mono.zip(issuer, thumbprint)
                            .flatMap {
                                verify(dPoPAuthentication, it.t1, it.t2)
                                    .then(Mono.just(dPoPAuthentication.authenticate(principal)))
                            }
                    }
            }

    /**
     * Introspects the provided [token] and verifies whether it's active or not.
     */
    private fun introspect(token: DPoPAccessToken): Mono<OAuth2AuthenticatedPrincipal> =
        introspector.introspect(token.value)
            .onErrorMap { exception ->
                val error =
                    if (exception is BadOpaqueTokenException) {
                        DPoPTokenError.invalidToken("Access token is not valid")
                    } else {
                        DPoPTokenError.serverError("Unable to introspect access token")
                    }
                OAuth2AuthenticationException(error, exception)
            }

    /**
     * Given a [DPoPTokenAuthentication], the [DPoPIssuer], and the [JWKThumbprintConfirmation], performs DPoP verification
     * using [verifier].
     */
    private fun verify(
        authentication: DPoPTokenAuthentication,
        issuer: DPoPIssuer,
        thumbprint: JWKThumbprintConfirmation,
    ): Mono<Unit> =
        Mono.fromCallable {
            verifier.verify(
                authentication.method.name(),
                authentication.uri,
                issuer,
                authentication.dpop,
                authentication.accessToken,
                thumbprint,
                null,
            )
        }.onErrorMap { exception ->
            val error =
                when (exception) {
                    is InvalidDPoPProofException -> DPoPTokenError.invalidToken("Invalid DPoP proof '${exception.message}'.")
                    is AccessTokenValidationException -> DPoPTokenError.invalidToken("Invalid access token binding '${exception.message}'.")
                    else -> DPoPTokenError.serverError("Unable to verify DPoP proof '${exception.message}'")
                }
            OAuth2AuthenticationException(error, exception)
        }
}

/**
 * Gets the [DPoPIssuer] from this [OAuth2AuthenticatedPrincipal].
 */
private fun OAuth2AuthenticatedPrincipal.issuer(): Mono<DPoPIssuer> =
    Mono.justOrEmpty(attributes[OAuth2TokenIntrospectionClaimNames.CLIENT_ID])
        .filter { it is String && it.isNotBlank() }
        .map { DPoPIssuer(ClientID(it as String)) }
        .switchIfEmpty {
            val error = DPoPTokenError.invalidToken("Unable to determine DPoP issuer")
            Mono.error(OAuth2AuthenticationException(error))
        }

/**
 * Gets the [JWKThumbprintConfirmation] from this [OAuth2AuthenticatedPrincipal].
 */
private fun OAuth2AuthenticatedPrincipal.jwkThumbprint(): Mono<JWKThumbprintConfirmation> =
    Mono.fromCallable { JSONObjectUtils.parse(JSONObject.toJSONString(attributes.filterKeys { it == "cnf" })) }
        .flatMap { Mono.fromCallable { JWKThumbprintConfirmation.parse(it) } }
        .onErrorMap {
            val error = DPoPTokenError.serverError("Unable to extract DPoP configuration")
            OAuth2AuthenticationException(error, it)
        }
        .switchIfEmpty {
            val error = DPoPTokenError.invalidToken("Access token is not DPoP bound")
            Mono.error(OAuth2AuthenticationException(error))
        }
