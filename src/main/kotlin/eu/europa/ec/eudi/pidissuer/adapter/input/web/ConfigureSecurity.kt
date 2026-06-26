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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier
import com.nimbusds.oauth2.sdk.dpop.verifiers.InMemoryDPoPSingleUseChecker
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.*
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.duration
import eu.europa.ec.eudi.pidissuer.log
import eu.europa.ec.eudi.pidissuer.port.out.nonce.GenerateNonce
import eu.europa.ec.eudi.pidissuer.port.out.nonce.VerifyNonce
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties
import org.springframework.core.env.Environment
import org.springframework.http.HttpStatus
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationConverterServerWebExchangeMatcher
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

fun configureSecurity(
    clock: Clock,
    env: Environment,
    http: ServerHttpSecurity,
    oAuth2ResourceServerProperties: OAuth2ResourceServerProperties,
    metadata: CredentialIssuerMetaData,
    dPoPConfigurationProperties: DPoPConfigurationProperties,
    webClient: org.springframework.web.reactive.function.client.WebClient,
    verifyNonce: VerifyNonce,
    generateNonce: GenerateNonce,
): SecurityWebFilterChain {
    fun Scope.springConvention() = "SCOPE_$value"
    val scopes =
        metadata.credentialConfigurationsSupported
            .map { it.scope.springConvention() }
            .distinct()

    return http {
        authorizeExchange {
            authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
            authorize(WalletApi.DEFERRED_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
            authorize(WalletApi.NOTIFICATION_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
            authorize(WalletApi.NONCE_ENDPOINT, permitAll)
            authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
            authorize(MetaDataApi.WELL_KNOWN_JWT_VC_ISSUER, permitAll)
            authorize(MetaDataApi.PUBLIC_KEYS, permitAll)
            authorize(MetaDataApi.TYPE_METADATA, permitAll)
            authorize(MetaDataApi.WELL_KNOWN_PROTECTED_RESOURCE_METADATA, permitAll)
            authorize(IssuerUi.GENERATE_CREDENTIALS_OFFER, permitAll)
            authorize(IssuerApi.CREATE_CREDENTIALS_OFFER, permitAll)
            authorize("", permitAll)
            authorize("/", permitAll)
            authorize(env.getRequiredProperty("spring.webflux.static-path-pattern"), permitAll)
            authorize(env.getRequiredProperty("spring.webflux.webjars-path-pattern"), permitAll)
            authorize(anyExchange, denyAll)
        }

        csrf {
            disable()
        }

        cors {
            disable()
        }

        val introspector = createTokenIntrospector(oAuth2ResourceServerProperties, webClient)

        log.info("Enabling DPoP AccessToken support")

        val dpopNonce =
            if (dPoPConfigurationProperties.dPoPNonceEnabled) {
                val dpopNonceExpiresIn = env.duration("issuer.dpop.nonce.expiration")
                val expiresIn = dpopNonceExpiresIn ?: 5.minutes
                DPoPNoncePolicy.Enforcing(verifyNonce, generateNonce, expiresIn)
            } else {
                DPoPNoncePolicy.Disabled
            }

        val entryPoint = DPoPTokenServerAuthenticationEntryPoint(dPoPConfigurationProperties.realm, dpopNonce, clock)
        val tokenConverter = ServerDPoPAuthenticationTokenAuthenticationConverter()

        val dpopFilter =
            createDpopFilter(clock, dPoPConfigurationProperties, introspector, dpopNonce, tokenConverter, entryPoint)
        http.addFilterAfter(dpopFilter, SecurityWebFiltersOrder.AUTHENTICATION)

        if (dpopNonce is DPoPNoncePolicy.Enforcing) {
            val dpopNonceFilter =
                DPoPNonceWebFilter(
                    dpopNonce,
                    clock,
                    listOf(
                        WalletApi.CREDENTIAL_ENDPOINT,
                        WalletApi.DEFERRED_ENDPOINT,
                        WalletApi.NOTIFICATION_ENDPOINT,
                        WalletApi.NONCE_ENDPOINT,
                    ),
                )
            http.addFilterAt(dpopNonceFilter, SecurityWebFiltersOrder.LAST)
        }

        exceptionHandling {
            authenticationEntryPoint =
                DelegatingServerAuthenticationEntryPoint(
                    listOf(
                        DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                            AuthenticationConverterServerWebExchangeMatcher(tokenConverter),
                            entryPoint,
                        ),
                    ),
                ).apply {
                    setDefaultEntryPoint(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
                }

            accessDeniedHandler =
                ServerWebExchangeDelegatingServerAccessDeniedHandler(
                    listOf(
                        ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                            AuthenticationConverterServerWebExchangeMatcher(tokenConverter),
                            DPoPTokenServerAccessDeniedHandler(dPoPConfigurationProperties.realm),
                        ),
                    ),
                ).apply {
                    setDefaultAccessDeniedHandler(HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN))
                }
        }
    }
}

private fun createDpopFilter(
    clock: Clock,
    dPoPConfigurationProperties: DPoPConfigurationProperties,
    introspector: SpringReactiveOpaqueTokenIntrospector,
    dpopNonce: DPoPNoncePolicy,
    tokenConverter: ServerDPoPAuthenticationTokenAuthenticationConverter,
    entryPoint: DPoPTokenServerAuthenticationEntryPoint,
): AuthenticationWebFilter {
    val dPoPVerifier =
        DPoPProtectedResourceRequestVerifier(
            dPoPConfigurationProperties.algorithms,
            15.seconds.inWholeSeconds,
            30.seconds.inWholeSeconds,
            InMemoryDPoPSingleUseChecker(
                60.seconds.inWholeSeconds,
                10.minutes.inWholeSeconds,
            ),
        )

    val authenticationManager =
        DPoPTokenReactiveAuthenticationManager(introspector, dPoPVerifier, dpopNonce, clock)

    return AuthenticationWebFilter(authenticationManager).apply {
        setServerAuthenticationConverter(tokenConverter)
        setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler(entryPoint))
    }
}

private fun createTokenIntrospector(
    introspectionProperties: OAuth2ResourceServerProperties,
    webClient: org.springframework.web.reactive.function.client.WebClient,
): SpringReactiveOpaqueTokenIntrospector {
    val introspectionEndpoint =
        checkNotNull(introspectionProperties.opaquetoken.introspectionUri) {
            "missing spring.security.oauth2.resourceserver.opaquetoken.introspection-uri configuration property"
        }
    return SpringReactiveOpaqueTokenIntrospector(
        introspectionEndpoint,
        webClient
            .mutate()
            .defaultHeaders {
                it.setBasicAuth(
                    introspectionProperties.opaquetoken.clientId!!,
                    introspectionProperties.opaquetoken.clientSecret!!,
                )
            }.build(),
    )
}
