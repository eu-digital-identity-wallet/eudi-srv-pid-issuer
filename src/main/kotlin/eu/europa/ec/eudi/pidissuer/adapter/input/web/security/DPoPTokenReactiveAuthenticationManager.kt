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
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.mono
import net.minidev.json.JSONObject
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector
import reactor.core.publisher.Mono

/**
 * [ReactiveAuthenticationManager] implementing DPoP authentication.
 * Implementation information can be found
 * [here](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/examples/oauth/dpop#rs).
 */
class DPoPTokenReactiveAuthenticationManager(
    private val introspector: SpringReactiveOpaqueTokenIntrospector,
    private val verifier: DPoPProtectedResourceRequestVerifier,
    private val dpopNonce: DPoPNoncePolicy,
) : ReactiveAuthenticationManager {

    /**
     * Performs DPoP authentication.
     */
    override fun authenticate(authentication: Authentication): Mono<Authentication> =
        mono {
            when (authentication) {
                is DPoPTokenAuthentication -> {
                    val principal = introspect(authentication.accessToken)
                    val issuer = principal.issuer()
                    val thumbprint = principal.jwkThumbprint()
                    val dpopNonce = dpopNonce.getActiveOrGenerateNew(authentication.accessToken)
                    verify(authentication, issuer, thumbprint, dpopNonce)
                    authentication.authenticate(principal)
                }
                else -> null
            }
        }

    /**
     * Introspects the provided [token] and verifies whether it's active or not.
     */
    private suspend fun introspect(token: DPoPAccessToken): OAuth2AuthenticatedPrincipal =
        try {
            introspector.introspect(token.value).awaitSingle()
        } catch (exception: BadOpaqueTokenException) {
            throw OAuth2AuthenticationException(DPoPTokenError.invalidToken("Access token is not valid"), exception)
        } catch (exception: Exception) {
            throw OAuth2AuthenticationException(DPoPTokenError.serverError("Unable to introspect access token", exception), exception)
        }

    /**
     * Given a [DPoPTokenAuthentication], the [DPoPIssuer], and the [JWKThumbprintConfirmation], performs DPoP verification
     * using [verifier].
     */
    private fun verify(
        authentication: DPoPTokenAuthentication,
        issuer: DPoPIssuer,
        thumbprint: JWKThumbprintConfirmation,
        dpopNonce: DPoPNonce?,
    ) {
        try {
            verifier.verify(
                authentication.method.name(),
                authentication.uri,
                issuer,
                authentication.dpop,
                authentication.accessToken,
                thumbprint,
                dpopNonce?.nonce,
            )
        } catch (exception: InvalidDPoPProofException) {
            val error = if (exception.message?.contains("nonce", ignoreCase = true) == true) {
                DPoPTokenError.useDPoPNonce("Invalid DPoP proof '${exception.message}'.", authentication.accessToken)
            } else {
                DPoPTokenError.invalidToken("Invalid DPoP proof '${exception.message}'.")
            }
            throw OAuth2AuthenticationException(error, exception)
        } catch (exception: AccessTokenValidationException) {
            throw OAuth2AuthenticationException(
                DPoPTokenError.invalidToken("Invalid access token binding '${exception.message}'."),
                exception,
            )
        } catch (exception: Exception) {
            throw OAuth2AuthenticationException(
                DPoPTokenError.serverError("Unable to verify DPoP proof '${exception.message}'", exception),
                exception,
            )
        }
    }
}

/**
 * Gets the [DPoPIssuer] from this [OAuth2AuthenticatedPrincipal].
 */
private fun OAuth2AuthenticatedPrincipal.issuer(): DPoPIssuer =
    attributes[OAuth2TokenIntrospectionClaimNames.CLIENT_ID]?.let { clientId ->
        if (clientId is String && clientId.isNotBlank()) {
            DPoPIssuer(ClientID(clientId))
        } else {
            null
        }
    } ?: throw OAuth2AuthenticationException(DPoPTokenError.invalidToken("Unable to determine DPoP issuer"))

/**
 * Gets the [JWKThumbprintConfirmation] from this [OAuth2AuthenticatedPrincipal].
 */
private fun OAuth2AuthenticatedPrincipal.jwkThumbprint(): JWKThumbprintConfirmation {
    val cnf = attributes.filterKeys { it == "cnf" }
        .takeIf { it.isNotEmpty() }
        ?: throw OAuth2AuthenticationException(DPoPTokenError.invalidToken("Access token is not DPoP bound"))

    return try {
        JWKThumbprintConfirmation.parse(JSONObject(cnf))
    } catch (exception: Exception) {
        throw OAuth2AuthenticationException(DPoPTokenError.serverError("Unable to extract DPoP confirmation", exception))
    }
}
