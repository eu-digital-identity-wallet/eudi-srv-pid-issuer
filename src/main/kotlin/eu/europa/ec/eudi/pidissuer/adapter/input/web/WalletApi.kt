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

import arrow.core.Either
import arrow.core.NonEmptySet
import arrow.core.raise.fold
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPTokenAuthentication
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import org.springframework.http.CacheControl
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.web.reactive.function.server.*
import org.springframework.web.server.ServerWebInputException
import kotlin.jvm.optionals.getOrNull

private val APPLICATION_JWT = MediaType.parseMediaType("application/jwt")

internal class WalletApi(
    private val issueCredential: IssueCredential,
    private val getDeferredCredential: GetDeferredCredential,
    private val getPidData: GetPidData,
    private val handleNotificationRequest: HandleNotificationRequest,
    private val handleNonceRequest: HandleNonceRequest,
) {

    val route = coRouter {
        POST(
            CREDENTIAL_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON, APPLICATION_JWT) and accept(MediaType.APPLICATION_JSON, APPLICATION_JWT),
            this@WalletApi::handleIssueCredential,
        )
        GET(
            CREDENTIAL_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            this@WalletApi::handleHelloHolder,
        )
        POST(
            DEFERRED_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON, APPLICATION_JWT) and accept(MediaType.APPLICATION_JSON, APPLICATION_JWT),
            this@WalletApi::handleGetDeferredCredential,
        )
        POST(
            NOTIFICATION_ENDPOINT,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.ALL),
            this@WalletApi::handleNotificationRequest,
        )
        POST(
            NONCE_ENDPOINT,
            contentType(MediaType.ALL) and accept(MediaType.APPLICATION_JSON),
        ) { handleNonceRequest() }
    }

    private suspend fun handleIssueCredential(req: ServerRequest): ServerResponse {
        val context = req.authorizationContext().getOrThrow()
        val response = try {
            when (req.headers().contentType().getOrNull()) {
                MediaType.APPLICATION_JSON -> {
                    val request = req.awaitBody<CredentialRequestTO>()
                    issueCredential.fromPlainRequest(context, request)
                }
                APPLICATION_JWT -> {
                    val jwt = req.awaitBody<String>()
                    issueCredential.fromEncryptedRequest(context, jwt)
                }
                else -> error("Unexpected content-type")
            }
        } catch (error: ServerWebInputException) {
            IssueCredentialResponse.FailedTO(
                type = CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST,
                errorDescription = buildString {
                    append("Request body could not be parsed")
                    if (error.message.isNotBlank()) {
                        append(": ${error.message}")
                    }
                },
            )
        }
        return response.toServerResponse()
    }

    private suspend fun handleGetDeferredCredential(req: ServerRequest): ServerResponse = coroutineScope {
        val response = try {
            when (req.headers().contentType().getOrNull()) {
                MediaType.APPLICATION_JSON -> {
                    val request = req.awaitBody<DeferredCredentialRequestTO>()
                    getDeferredCredential.fromPlainRequest(request)
                }
                APPLICATION_JWT -> {
                    val jwt = req.awaitBody<String>()
                    getDeferredCredential.fromEncryptedRequest(jwt)
                }
                else -> error("Unexpected content-type")
            }
        } catch (error: ServerWebInputException) {
            DeferredCredentialResponse.Failed(
                FailedTO(
                    type = GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST,
                    errorDescription = buildString {
                        append("Request body could not be parsed")
                        if (error.message.isNotBlank()) {
                            append(": ${error.message}")
                        }
                    },
                ),
            )
        }
        response.toServerResponse()
    }

    private suspend fun handleHelloHolder(req: ServerRequest): ServerResponse = coroutineScope {
        val context = async { req.authorizationContext().getOrThrow() }
        val pid = getPidData(context.await().username)
        if (null != pid) ServerResponse.ok()
            .cacheControl(CacheControl.noStore())
            .json()
            .bodyValueAndAwait(pid)
        else ServerResponse.notFound()
            .cacheControl(CacheControl.noStore())
            .buildAndAwait()
    }

    private suspend fun handleNotificationRequest(request: ServerRequest): ServerResponse =
        when (val response = handleNotificationRequest(request.awaitBody<JsonElement>())) {
            is NotificationResponse.Success -> ServerResponse.noContent()
                .cacheControl(CacheControl.noStore())
                .buildAndAwait()
            is NotificationResponse.NotificationErrorResponseTO ->
                ServerResponse.badRequest()
                    .cacheControl(CacheControl.noStore())
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValueAndAwait(response)
        }

    private suspend fun handleNonceRequest(): ServerResponse =
        ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .cacheControl(CacheControl.noStore())
            .bodyValueAndAwait(handleNonceRequest.invoke())

    companion object {
        const val CREDENTIAL_ENDPOINT = "/wallet/credentialEndpoint"
        const val DEFERRED_ENDPOINT = "/wallet/deferredEndpoint"
        const val NOTIFICATION_ENDPOINT = "/wallet/notificationEndpoint"
        const val NONCE_ENDPOINT = "/wallet/nonceEndpoint"
    }
}

private suspend fun ServerRequest.authorizationContext(): Either<Throwable, AuthorizationContext> =
    Either.catch {
        val authentication = awaitPrincipal()

        requireNotNull(authentication) { "Authentication is expected" }

        fun fromSpring(authority: GrantedAuthority): Scope? =
            authority.authority
                .takeIf { it.startsWith("SCOPE_") }
                ?.replaceFirst("SCOPE_", "")
                ?.let { Scope(it) }

        data class AuthenticationDetails(
            val scopes: NonEmptySet<Scope>? = null,
            val clientId: Any? = null,
            val username: Any? = null,
            val accessToken: AccessToken,
        )

        val (scopes, clientId, username, accessToken) = when (authentication) {
            is DPoPTokenAuthentication ->
                AuthenticationDetails(
                    authentication.authorities.mapNotNull { fromSpring(it) }.toNonEmptySetOrNull(),
                    authentication.principal?.attributes?.get(OAuth2TokenIntrospectionClaimNames.CLIENT_ID),
                    authentication.name,
                    authentication.accessToken,
                )

            is BearerTokenAuthentication ->
                AuthenticationDetails(
                    authentication.authorities.mapNotNull { fromSpring(it) }.toNonEmptySetOrNull(),
                    authentication.tokenAttributes[OAuth2TokenIntrospectionClaimNames.CLIENT_ID],
                    authentication.tokenAttributes[OAuth2TokenIntrospectionClaimNames.USERNAME],
                    BearerAccessToken.parse("${authentication.token.tokenType.value} ${authentication.token.tokenValue}"),
                )

            else -> error("Unexpected Authentication type '${authentication::class.java}'")
        }

        requireNotNull(scopes) { "OAuth2 scopes are expected" }
        require(clientId is String) { "Unexpected client_id claim type '${clientId?.let { it::class.java }}'" }
        require(username is String) { "Unexpected username claim type '${username?.let { it::class.java }}'" }

        AuthorizationContext(username, accessToken, scopes, clientId)
    }

private suspend fun IssueCredentialResponse.toServerResponse(): ServerResponse =
    when (this) {
        is IssueCredentialResponse.PlainTO ->
            ServerResponse
                .status(transactionId?.let { HttpStatus.ACCEPTED } ?: HttpStatus.OK)
                .cacheControl(CacheControl.noStore())
                .json()
                .bodyValueAndAwait(this)

        is IssueCredentialResponse.EncryptedJwtIssued ->
            ServerResponse
                .ok()
                .cacheControl(CacheControl.noStore())
                .contentType(APPLICATION_JWT)
                .bodyValueAndAwait(jwt)

        is IssueCredentialResponse.FailedTO ->
            ServerResponse
                .badRequest()
                .cacheControl(CacheControl.noStore())
                .json()
                .bodyValueAndAwait(this)
    }

private suspend fun DeferredCredentialResponse.toServerResponse(): ServerResponse =
    when (this) {
        is DeferredCredentialResponse.Issued -> content.fold(
            ifLeft = { json ->
                ServerResponse
                    .ok()
                    .cacheControl(CacheControl.noStore())
                    .json()
                    .bodyValueAndAwait(json)
            },
            ifRight = { jwt ->
                ServerResponse
                    .ok()
                    .cacheControl(CacheControl.noStore())
                    .contentType(APPLICATION_JWT)
                    .bodyValueAndAwait(jwt.serialize())
            },
        )
        is DeferredCredentialResponse.IssuancePending -> content.fold(
            ifLeft = { json ->
                ServerResponse
                    .status(HttpStatus.ACCEPTED)
                    .cacheControl(CacheControl.noStore())
                    .json()
                    .bodyValueAndAwait(json)
            },
            ifRight = { jwt ->
                ServerResponse
                    .status(HttpStatus.ACCEPTED)
                    .cacheControl(CacheControl.noStore())
                    .contentType(APPLICATION_JWT)
                    .bodyValueAndAwait(jwt.serialize())
            },
        )
        is DeferredCredentialResponse.Failed ->
            ServerResponse
                .badRequest()
                .cacheControl(CacheControl.noStore())
                .json()
                .bodyValueAndAwait(this.content)
    }
