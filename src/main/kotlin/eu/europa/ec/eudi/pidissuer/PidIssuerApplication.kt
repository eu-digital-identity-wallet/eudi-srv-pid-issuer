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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateJwtProofWithNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidDataFromAuthServer
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.IssueMsoMdocPid
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.issueSdJwtVcPid
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.GetCredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredential
import eu.europa.ec.eudi.pidissuer.port.input.RequestCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenCNonce
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.GenericApplicationContext
import org.springframework.context.support.beans
import org.springframework.core.env.getRequiredProperty
import org.springframework.http.HttpStatus
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import java.net.URL
import java.time.Clock
import java.time.Duration
import java.util.*

fun beans(clock: Clock) = beans {
    bean { clock }
    bean {
        val issuerPublicUrl = env.getRequiredProperty("issuer.publicUrl").run { HttpsUrl.unsafe(this) }
        val issueMsoMdocPid = IssueMsoMdocPid(ref())
        val issueSdJwtVcPid = issueSdJwtVcPid(
            hashAlgorithm = HashAlgorithm.SHA3_256,
            issuerKey = ECKeyGenerator(Curve.P_256).keyID("issuer-kid-0").generate(),
            getPidData = ref(),
            clock = clock,
            signAlg = JWSAlgorithm.ES256,
            credentialIssuerId = issuerPublicUrl,
            validateJwtProof = ValidateJwtProofWithNimbus(issuerPublicUrl),
        )
        bean { issueMsoMdocPid }
        bean { issueSdJwtVcPid }
        val authorizationServer = env.getRequiredProperty("issuer.authorizationServer").run { HttpsUrl.unsafe(this) }
        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = env.getRequiredProperty("issuer.publicUrl")
                .run { HttpsUrl.unsafe("$this/wallet/credentialEndpoint") },
            authorizationServer = authorizationServer,
            specificCredentialIssuers = listOf(issueMsoMdocPid, issueSdJwtVcPid),
        )
    }

    //
    // Adapters (out ports)
    //
    bean {
        val userinfoEndpoint = env.getRequiredProperty<URL>("issuer.authorizationServer.userinfo")
        GetPidDataFromAuthServer(userinfoEndpoint)
    }
    bean {
        GenCNonce { accessToken, clock ->
            CNonce(accessToken, UUID.randomUUID().toString(), clock.instant(), Duration.ofMinutes(5L))
        }
    }
    bean {
        val repo = InMemoryCNonceRepository()
        bean { repo }
        bean { repo.deleteExpiredCNonce }
        bean { repo.upsertCNonce }
        bean { repo.loadCNonceByAccessToken }
    }

    //
    // In Ports (use cases)
    //
    bean(::GetCredentialIssuerMetaData)
    bean(::RequestCredentialsOffer)
    bean {
        val credentialIssuerMetaData = ref<CredentialIssuerMetaData>()
        val specificCredentialIssuers = credentialIssuerMetaData.specificCredentialIssuers
        IssueCredential(clock, specificCredentialIssuers, ref(), ref(), ref())
    }

    //
    // Routes
    //
    bean {
        val metaDataApi = MetaDataApi(ref())
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
        val metaData = ref<CredentialIssuerMetaData>()
        val scopes = metaData.credentialsSupported
            .mapNotNull { it.scope?.springConvention() }
            .distinct()
        val http = ref<ServerHttpSecurity>()
        http {
            authorizeExchange {
                authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWKS, permitAll)
                authorize(IssuerApi.CREDENTIALS_OFFER, permitAll)
                authorize(anyExchange, denyAll)
            }

            csrf {
                disable()
            }

            cors {
                disable()
            }

            exceptionHandling {
                authenticationEntryPoint = HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)
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
        addInitializers(beans(Clock.systemDefaultZone()).initializer())
    }
}
