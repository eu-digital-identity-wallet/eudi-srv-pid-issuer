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

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.out.idp.GetPidDataFromAuthServer
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.GenericApplicationContext
import org.springframework.context.support.beans
import org.springframework.core.env.getRequiredProperty
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import java.net.URL
import java.time.Clock
import java.util.*

private fun rsaJwk(clock: Clock): RSAKey =
    RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date.from(clock.instant())) // issued-at timestamp (optional)
        .generate()

val beans = beans {

    bean {
        val issuingServices = provider<IssueSpecificCredential>().toList()
        val clock = Clock.systemDefaultZone()
        val sdJwtVcSigningKey = rsaJwk(clock)
        val issuerPublicUrl = env.getRequiredProperty("issuer.publicUrl").run { HttpsUrl.unsafe(this) }
        val authorizationServer = env.getRequiredProperty("issuer.authorizationServer").run { HttpsUrl.unsafe(this) }
        val credentialIssuerMetaData = CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = env.getRequiredProperty("issuer.publicUrl")
                .run { HttpsUrl.unsafe("$this/wallet/credentialEndpoint") },
            authorizationServer = authorizationServer,
            credentialsSupported = issuingServices.map { it.supportedCredential },
        )
        CredentialIssuerContext(
            metaData = credentialIssuerMetaData,
            clock = clock,
            sdJwtVcSigningKey = sdJwtVcSigningKey,
            issuingServices = issuingServices,
        )
    }

    //
    // Adapters (out ports)
    //
    bean {
        val userinfoEndpoint = env.getRequiredProperty<URL>("issuer.authorizationServer.userinfo")
        GetPidDataFromAuthServer(userinfoEndpoint)
    }
    bean(::GetJwkSet)
    bean { InMemoryCNonceRepository() }

    //
    // In Ports (use cases)
    //
    bean(::GetCredentialIssuerMetaData)
    bean(::RequestCredentialsOffer)
    bean(::IssueMsoMdocPid)
    bean(::IssueSdJwtVcPid)

    bean(::IssueCredential)
    bean(::HelloHolder)

    //
    // Routes
    //
    bean {
        val metaDataApi = MetaDataApi(ref(), ref())
        val walletApi = WalletApi(ref(), ref())
        val issuerApi = IssuerApi(ref())
        metaDataApi.route.and(issuerApi.route).and(walletApi.route)
    }

    //
    // Security
    //
    bean {

        /*
         * This is Spring naming convention
         * A prefix of SCOPE_xyz will grant a SimpleAuthority(xyz)
         * if there is a scope xyz
         *
         * Note that on the OAUTH2 server we set xyz as te scope
         * and not SCOPE_xyz
         */
        fun Scope.springConvention() = "SCOPE_$value"
        val ctx = ref<CredentialIssuerContext>()
        val scopes = ctx.metaData.credentialsSupported
            .mapNotNull { it.scope?.springConvention() }
            .distinct()
        val http = ref<ServerHttpSecurity>()
        http {
            authorizeExchange {
                authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWKS, permitAll)
                authorize(IssuerApi.CREDENTIALS_OFFER, permitAll)
            }

            oauth2ResourceServer {
                opaqueToken {}
            }
        }
    }

    //
    // Other
    //
    bean {
        object : WebFluxConfigurer {
            @OptIn(ExperimentalSerializationApi::class)
            override fun configureHttpMessageCodecs(configurer: ServerCodecConfigurer) {
                val json = Json {
                    explicitNulls = false
                    ignoreUnknownKeys = true
                }
                configurer.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
                configurer.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
                configurer.defaultCodecs().enableLoggingRequestDetails(true)
            }
        }
    }
}

fun BeanDefinitionDsl.initializer(): ApplicationContextInitializer<GenericApplicationContext> =
    ApplicationContextInitializer<GenericApplicationContext> { initialize(it) }

@SpringBootApplication
@EnableWebFlux
@EnableWebFluxSecurity
class PidIssuerApplication

fun main(args: Array<String>) {
    runApplication<PidIssuerApplication>(*args) {
        addInitializers(beans.initializer())
    }
}
