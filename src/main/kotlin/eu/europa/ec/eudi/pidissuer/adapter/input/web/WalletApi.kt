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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.raise.result
import arrow.core.toNonEmptySetOrNull
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.CredentialRequestTO
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredential
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.web.reactive.function.server.*

private val APPLICATION_JWT = MediaType.parseMediaType("application/jwt")

class WalletApi(
    private val issueCredential: IssueCredential,
    private val getPidData: GetPidData,

) {

    val route = coRouter {
        POST(
            CREDENTIAL_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON, APPLICATION_JWT),
            this@WalletApi::handleIssueCredential,
        )
        GET(
            CREDENTIAL_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            this@WalletApi::handleHelloHolder,
        )
    }

    private suspend fun handleIssueCredential(req: ServerRequest): ServerResponse {
        val context = req.authorizationContext().getOrThrow()
        val credentialRequest = req.awaitBody(CredentialRequestTO::class)
        return when (val response = issueCredential(context, credentialRequest)) {
            is IssueCredentialResponse.PlainTO ->
                ServerResponse
                    .status(response.credential?.let { HttpStatus.OK } ?: HttpStatus.ACCEPTED)
                    .json()
                    .bodyValueAndAwait(response)

            is IssueCredentialResponse.EncryptedJwtIssued ->
                ServerResponse
                    .ok()
                    .contentType(APPLICATION_JWT)
                    .bodyValueAndAwait(response.jwt)

            is IssueCredentialResponse.FailedTO ->
                ServerResponse
                    .badRequest()
                    .json()
                    .bodyValueAndAwait(response)
        }
    }

    private suspend fun handleHelloHolder(req: ServerRequest): ServerResponse = coroutineScope {
        val context = async { req.authorizationContext().getOrThrow() }
        val pid = getPidData(context.await().accessToken)
        if (null != pid) ServerResponse.ok().json().bodyValueAndAwait(pid)
        else ServerResponse.notFound().buildAndAwait()
    }

    companion object {
        const val CREDENTIAL_ENDPOINT = "/wallet/credentialEndpoint"
    }
}

private suspend fun ServerRequest.authorizationContext(): Result<AuthorizationContext> =
    result {
        val principal = awaitPrincipal()
        ensureNotNull(principal) { IllegalArgumentException("Principal is expected") }
        ensure(principal is BearerTokenAuthentication) { IllegalArgumentException("Unexpected Principal type '${principal::class.java}'") }

        val accessToken: OAuth2AccessToken = principal.token
        ensure(accessToken.tokenType == TokenType.BEARER) {
            IllegalArgumentException("Unexpected AccessToken type '${accessToken.tokenType.value}'")
        }

        fun fromSpring(authority: GrantedAuthority): Scope? =
            authority.authority
                .takeIf { it.startsWith("SCOPE_") }
                ?.replaceFirst("SCOPE_", "")
                ?.let { Scope(it) }

        val scopes = principal.authorities.mapNotNull { fromSpring(it) }.toNonEmptySetOrNull()
        ensureNotNull(scopes) { IllegalArgumentException("OAuth2 scopes are expected") }

        val clientId = principal.tokenAttributes[OAuth2TokenIntrospectionClaimNames.CLIENT_ID]
        ensure(clientId is String) { IllegalArgumentException("Unexpected client_id claim type '${clientId?.let { it::class.java }}'") }

        AuthorizationContext(accessToken.tokenValue, scopes, clientId)
    }
