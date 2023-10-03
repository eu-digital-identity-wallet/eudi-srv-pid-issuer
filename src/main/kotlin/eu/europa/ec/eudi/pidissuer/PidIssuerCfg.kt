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
package eu.europa.ec.eudi.pidissuer

import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.port.input.GetCredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredential
import eu.europa.ec.eudi.pidissuer.port.input.RequestCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.out.cfg.GetCredentialIssuerContext
import eu.europa.ec.eudi.pidissuer.port.out.cfg.GetCredentialIssuerContextFromEnv
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.function.server.RouterFunction

@Configuration
@EnableWebFlux
class MyConfig : WebFluxConfigurer {
    override fun configureHttpMessageCodecs(configurer: ServerCodecConfigurer) {
        configurer.defaultCodecs().enableLoggingRequestDetails(true)
    }
}

@Configuration
@EnableScheduling
class ScheduleSupport

@Configuration
class PidIssuerContext(private val environment: Environment) {

    @Bean
    fun route(walletApi: WalletApi, issuerApi: IssuerApi, metaDataApi: MetaDataApi): RouterFunction<*> =
        metaDataApi.route.and(issuerApi.route).and(walletApi.route)

    //
    // End Points
    //
    @Bean
    fun genericApi(getCredentialIssuerMetaData: GetCredentialIssuerMetaData) =
        MetaDataApi(getCredentialIssuerMetaData)

    @Bean
    fun issuerApi(requestCredentialsOffer: RequestCredentialsOffer): IssuerApi = IssuerApi(requestCredentialsOffer)

    @Bean
    fun walletApi(issueCredential: IssueCredential): WalletApi = WalletApi(issueCredential)

    //
    // In Ports (use cases)
    //
    @Bean
    fun getCredentialIssuerMetaData(getCredentialIssuerContext: GetCredentialIssuerContext) =
        GetCredentialIssuerMetaData(getCredentialIssuerContext)

    @Bean
    fun requestCredentialsOffer(getCredentialIssuerContext: GetCredentialIssuerContext) =
        RequestCredentialsOffer(getCredentialIssuerContext)

    @Bean
    fun issueCredential() = IssueCredential()

    //
    // Adapters (out ports)
    //
    @Bean
    fun getCredentialIssuerContext(): GetCredentialIssuerContext =
        GetCredentialIssuerContextFromEnv(environment)
}

@Configuration
@EnableWebFluxSecurity
class SecurityCfg {

    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    fun protectedApi(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            authorizeExchange {
                authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAuthority(PidMsoMdocV1.scope!!.toSpring()))
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(IssuerApi.CREDENTIALS_OFFER, permitAll)
            }

            oauth2ResourceServer {
                opaqueToken {}
            }
        }
    }

    /**
     * This is Spring naming convention
     * A prefix of SCOPE_xyz will grant a SimpleAuthority(xyz)
     * if there is a scope xyz
     *
     * Note that on the OAUTH2 server we set xyz as te scope
     * and not SCOPE_xyz
     */
    private fun Scope.toSpring() = "SCOPE_$value"
}

@Configuration
class JsonConfiguration : WebFluxConfigurer {
    @OptIn(ExperimentalSerializationApi::class)
    override fun configureHttpMessageCodecs(configurer: ServerCodecConfigurer) {
        val json = Json {
            explicitNulls = false
            ignoreUnknownKeys = true
        }
        configurer.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
        configurer.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
    }
}
