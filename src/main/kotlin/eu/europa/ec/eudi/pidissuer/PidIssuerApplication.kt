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

import arrow.core.NonEmptySet
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.DefaultExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.EncryptCredentialResponseWithNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryDeferredCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.GetCredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.GetDeferredCredential
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredential
import eu.europa.ec.eudi.pidissuer.port.input.RequestCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.out.asDeferred
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateCNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.GenericApplicationContext
import org.springframework.context.support.beans
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
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
import java.time.Clock
import java.time.Duration

fun beans(clock: Clock) = beans {
    //
    // Adapters (out ports)
    //
    bean { clock }
    bean {
        GetPidDataFromAuthServer(
            env.readRequiredUrl("issuer.authorizationServer.userinfo"),
            env.getRequiredProperty("issuer.pid.issuingCountry").let(::IsoCountry),
            clock,
        )
    }
    //
    // Encryption of credential response
    //
    bean(isLazyInit = true) {
        EncryptCredentialResponseWithNimbus(ref<CredentialIssuerMetaData>().id, clock)
    }
    //
    // CNonce
    //
    with(InMemoryCNonceRepository()) {
        bean { deleteExpiredCNonce }
        bean { upsertCNonce }
        bean { loadCNonceByAccessToken }
        bean { GenerateCNonce.random(Duration.ofMinutes(5L)) }
        bean { this@with } // this is needed for test
    }

    //
    // Deferred Credentials
    //
    with(InMemoryDeferredCredentialRepository(mutableMapOf(TransactionId("foo") to null))) {
        bean { GenerateTransactionId.Random }
        bean { storeDeferredCredential }
        bean { loadDeferredCredentialByTransactionId }
    }

    //
    // Specific Issuers
    //
    bean {
        val issuerPublicUrl = env.readRequiredUrl("issuer.publicUrl")

        bean {
            EncodePidInCborWithMicroService(env.readRequiredUrl("issuer.pid.mso_mdoc.encoderUrl"))
        }

        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = env.readRequiredUrl("issuer.publicUrl").run {
                HttpsUrl.unsafe("${this.value}${WalletApi.CREDENTIAL_ENDPOINT}")
            },
            deferredCredentialEndpoint = env.readRequiredUrl("issuer.publicUrl").run {
                HttpsUrl.unsafe("${this.value}${WalletApi.DEFERRED_ENDPOINT}")
            },
            authorizationServer = env.readRequiredUrl("issuer.authorizationServer"),

            credentialResponseEncryption = env.credentialResponseEncryption(),
            specificCredentialIssuers = buildList {
                val enableMsoMdocPid = env.getProperty<Boolean>("issuer.pid.mso_mdoc.enabled") ?: true
                if (enableMsoMdocPid) {
                    val issueMsoMdocPid = IssueMsoMdocPid(
                        credentialIssuerId = issuerPublicUrl,
                        getPidData = ref(),
                        encodePidInCbor = ref(),
                    )
                    add(issueMsoMdocPid)
                }
                val enableSdJwtVcPid = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.enabled") ?: true
                if (enableSdJwtVcPid) {
                    val notUseBefore = env.getProperty("issuer.pid.sd_jwt_vc.notUseBefore")?.let {
                        runCatching {
                            Duration.parse(it).takeUnless { it.isZero || it.isNegative }
                        }.getOrNull()
                    }

                    val sdOption =
                        env.getProperty<SelectiveDisclosureOption>("issuer.pid.sd_jwt_vc.complexObjectsSdOption")
                            ?: SelectiveDisclosureOption.Structured

                    val issueSdJwtVcPid = IssueSdJwtVcPid(
                        hashAlgorithm = HashAlgorithm.SHA3_256,
                        issuerKey = ECKeyGenerator(Curve.P_256).keyID("issuer-kid-0").generate(),
                        getPidData = ref(),
                        clock = clock,
                        signAlg = JWSAlgorithm.ES256,
                        credentialIssuerId = issuerPublicUrl,
                        extractJwkFromCredentialKey = DefaultExtractJwkFromCredentialKey,
                        calculateExpiresAt = { iat -> iat.plusDays(30).toInstant() },
                        calculateNotUseBefore = notUseBefore?.let { duration ->
                            {
                                    iat ->
                                iat.plusSeconds(duration.seconds).toInstant()
                            }
                        },
                        sdOption = sdOption,
                    )
                    val deferred = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.deferred") ?: false
                    add(
                        if (deferred) issueSdJwtVcPid.asDeferred(ref(), ref())
                        else issueSdJwtVcPid,
                    )
                }
            },
        )
    }

    //
    // In Ports (use cases)
    //
    bean(::GetCredentialIssuerMetaData)
    bean(::RequestCredentialsOffer)
    bean {
        IssueCredential(clock, ref(), ref(), ref(), ref(), ref())
    }
    bean {
        GetDeferredCredential(ref())
    }

    //
    // Routes
    //
    bean {
        val metaDataApi = MetaDataApi(ref())
        val walletApi = WalletApi(ref(), ref(), ref())
        val issuerApi = IssuerApi(ref())
        metaDataApi.route.and(issuerApi.route).and(walletApi.route)
    }

    //
    // Security
    //
    bean {
        /*
         * This is a Spring naming convention
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
                authorize(WalletApi.DEFERRED_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
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

private fun Environment.credentialResponseEncryption(): CredentialResponseEncryption {
    val isRequired = getProperty<Boolean>("issuer.credentialResponseEncryption.required") ?: false
    return if (!isRequired)
        CredentialResponseEncryption.NotRequired
    else
        CredentialResponseEncryption.Required(
            algorithmsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.algorithmsSupported",
                JWEAlgorithm::parse,
            ),
            encryptionMethods = readNonEmptySet(
                "issuer.credentialResponseEncryption.encryptionMethods",
                EncryptionMethod::parse,
            ),
        )
}

private fun Environment.readRequiredUrl(key: String): HttpsUrl =
    getRequiredProperty(key).let { url ->
        HttpsUrl.of(url) ?: HttpsUrl.unsafe(url)
    }

private fun <T> Environment.readNonEmptySet(key: String, f: (String) -> T?): NonEmptySet<T> {
    val nonEmptySet = getRequiredProperty<MutableSet<String>>(key)
        .mapNotNull(f)
        .toNonEmptySetOrNull()
    return checkNotNull(nonEmptySet) { "Missing or incorrect values values for key `$key`" }
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
