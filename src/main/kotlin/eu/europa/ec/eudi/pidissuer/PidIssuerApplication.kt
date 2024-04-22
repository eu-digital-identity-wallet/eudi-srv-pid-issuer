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
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.CredentialRequestFactory
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.DefaultResolveCredentialRequestByCredentialIdentifier
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.DefaultExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.EncryptCredentialResponseWithNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.*
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryDeferredCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryIssuedCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.adapter.out.qr.DefaultGenerateQrCode
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.asDeferred
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateCNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.security.*
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import jakarta.ws.rs.client.Client
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.TrustAllStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.keycloak.OAuth2Constants
import org.keycloak.admin.client.KeycloakBuilder
import org.keycloak.admin.client.spi.ResteasyClientClassicProvider
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import org.springframework.boot.web.codec.CodecCustomizer
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.GenericApplicationContext
import org.springframework.context.support.beans
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.env.getRequiredProperty
import org.springframework.http.HttpStatus
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenReactiveAuthenticationManager
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.AuthenticationConverterServerWebExchangeMatcher
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import reactor.netty.http.client.HttpClient
import java.net.URL
import java.time.Clock
import java.time.Duration

private val log = LoggerFactory.getLogger(PidIssuerApplication::class.java)

/**
 * [WebClient] instances for usage within the application.
 */
internal object WebClients {

    /**
     * A [WebClient] with [Json] serialization enabled.
     */
    val Default: WebClient by lazy {
        val json = Json { ignoreUnknownKeys = true }
        WebClient
            .builder()
            .codecs {
                it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
                it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
                it.defaultCodecs().enableLoggingRequestDetails(true)
            }
            .build()
    }

    /**
     * A [WebClient] with [Json] serialization enabled that trusts *all* certificates.
     */
    val Insecure: WebClient by lazy {
        log.warn("Using insecure WebClient trusting all certificates")
        val sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        val httpClient = HttpClient.create().secure { it.sslContext(sslContext) }
        Default.mutate()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .build()
    }
}

/**
 * [Client] instances for usage within the application.
 */
internal object RestEasyClients {

    /**
     * A [Client].
     */
    val Default: Client by lazy {
        ResteasyClientClassicProvider().newRestEasyClient(null, null, false)
    }

    /**
     * A [Client] that trusts *all* certificates.
     */
    val Insecure: Client by lazy {
        log.warn("Using insecure RestEasy Client trusting all certificates")
        val sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(TrustAllStrategy())
            .build()
        ResteasyClientClassicProvider().newRestEasyClient(null, sslContext, true)
    }
}

@OptIn(ExperimentalSerializationApi::class)
fun beans(clock: Clock) = beans {
    //
    // Adapters (out ports)
    //
    bean { clock }
    bean {
        if ("insecure" in env.activeProfiles) {
            WebClients.Insecure
        } else {
            WebClients.Default
        }
    }
    bean {
        if ("insecure" in env.activeProfiles) {
            RestEasyClients.Insecure
        } else {
            RestEasyClients.Default
        }
    }
    bean {
        val keycloakProperties = ref<KeycloakConfigurationProperties>()
        val keycloak = KeycloakBuilder.builder()
            .serverUrl(keycloakProperties.serverUrl.toExternalForm())
            .realm(keycloakProperties.authenticationRealm)
            .clientId(keycloakProperties.clientId)
            .grantType(OAuth2Constants.PASSWORD)
            .username(keycloakProperties.username)
            .password(keycloakProperties.password)
            .resteasyClient(ref())
            .build()

        GetPidDataFromAuthServer(
            env.getRequiredProperty("issuer.pid.issuingCountry").let(::IsoCountry),
            clock,
            keycloak,
            keycloakProperties.userRealm,
        )
    }
    bean {
        EncodePidInCborWithMicroService(env.readRequiredUrl("issuer.pid.mso_mdoc.encoderUrl"), ref())
    }
    bean {
        GetMobileDrivingLicenceDataMock()
    }
    bean {
        EncodeMobileDrivingLicenceInCborWithMicroservice(
            ref(),
            env.readRequiredUrl("issuer.mdl.mso_mdoc.encoderUrl"),
        )
    }
    bean(::DefaultGenerateQrCode)
    bean(::HandleNotificationRequest)
    bean {
        val resolvers = buildMap<CredentialIdentifier, CredentialRequestFactory> {
            this[CredentialIdentifier(MobileDrivingLicenceV1Scope.value)] =
                { unvalidatedProof, requestedResponseEncryption ->
                    MsoMdocCredentialRequest(
                        unvalidatedProof = unvalidatedProof,
                        credentialResponseEncryption = requestedResponseEncryption,
                        docType = MobileDrivingLicenceV1.docType,
                        claims = MobileDrivingLicenceV1.msoClaims.mapValues { entry -> entry.value.map { attribute -> attribute.name } },
                    )
                }

            this[CredentialIdentifier(PidMsoMdocScope.value)] =
                { unvalidatedProof, requestedResponseEncryption ->
                    MsoMdocCredentialRequest(
                        unvalidatedProof = unvalidatedProof,
                        credentialResponseEncryption = requestedResponseEncryption,
                        docType = PidMsoMdocV1.docType,
                        claims = PidMsoMdocV1.msoClaims.mapValues { entry -> entry.value.map { attribute -> attribute.name } },
                    )
                }

            pidSdJwtVcV1(JWSAlgorithm.ES256).let { sdJwtVcPid ->
                this[CredentialIdentifier(PidSdJwtVcScope.value)] =
                    { unvalidatedProof, requestedResponseEncryption ->
                        SdJwtVcCredentialRequest(
                            unvalidatedProof = unvalidatedProof,
                            credentialResponseEncryption = requestedResponseEncryption,
                            type = sdJwtVcPid.type,
                            claims = sdJwtVcPid.claims.map { it.name }.toSet(),
                        )
                    }
            }
        }

        DefaultResolveCredentialRequestByCredentialIdentifier(resolvers)
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
    // Credentials
    //
    with(InMemoryIssuedCredentialRepository()) {
        bean { GenerateNotificationId.Random }
        bean { storeIssuedCredential }
        bean { loadIssuedCredentialByNotificationId }
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
        val issuerPublicUrl = env.readRequiredUrl("issuer.publicUrl", removeTrailingSlash = true)

        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = issuerPublicUrl.appendPath(WalletApi.CREDENTIAL_ENDPOINT),
            deferredCredentialEndpoint = issuerPublicUrl.appendPath(WalletApi.DEFERRED_ENDPOINT),
            notificationEndpoint = issuerPublicUrl.appendPath(WalletApi.NOTIFICATION_ENDPOINT),
            authorizationServers = listOf(env.readRequiredUrl("issuer.authorizationServer")),
            credentialResponseEncryption = env.credentialResponseEncryption(),
            specificCredentialIssuers = buildList {
                val enableMsoMdocPid = env.getProperty<Boolean>("issuer.pid.mso_mdoc.enabled") ?: true
                if (enableMsoMdocPid) {
                    val issueMsoMdocPid = IssueMsoMdocPid(
                        credentialIssuerId = issuerPublicUrl,
                        getPidData = ref(),
                        encodePidInCbor = ref(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.mso_mdoc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        clock = clock,
                        storeIssuedCredential = ref(),
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
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        storeIssuedCredential = ref(),
                    )
                    val deferred = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.deferred") ?: false
                    add(
                        if (deferred) issueSdJwtVcPid.asDeferred(ref(), ref())
                        else issueSdJwtVcPid,
                    )
                }

                val enableMobileDrivingLicence = env.getProperty("issuer.mdl.enabled", true)
                if (enableMobileDrivingLicence) {
                    val mdlIssuer = IssueMobileDrivingLicence(
                        credentialIssuerId = issuerPublicUrl,
                        getMobileDrivingLicenceData = ref(),
                        encodeMobileDrivingLicenceInCbor = ref(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.mdl.notifications.enabled") ?: true,
                        generateNotificationId = ref(),
                        clock = clock,
                        storeIssuedCredential = ref(),
                    )
                    add(mdlIssuer)
                }
            },
        )
    }

    //
    // In Ports (use cases)
    //
    bean(::GetCredentialIssuerMetaData)
    bean {
        IssueCredential(clock, ref(), ref(), ref(), ref(), ref(), ref())
    }
    bean(::GetDeferredCredential)
    bean {
        CreateCredentialsOffer(ref(), env.getRequiredProperty<String>("issuer.credentialOffer.uri"))
    }

    //
    // Routes
    //
    bean {
        val metaDataApi = MetaDataApi(ref(), ref())
        val walletApi = WalletApi(ref(), ref(), ref(), ref())
        val issuerUi = IssuerUi(ref(), ref(), ref())
        val issuerApi = IssuerApi(ref())
        metaDataApi.route.and(walletApi.route).and(issuerUi.router).and(issuerApi.router)
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
        val scopes = metaData.credentialConfigurationsSupported
            .mapNotNull { it.scope?.springConvention() }
            .distinct()
        val http = ref<ServerHttpSecurity>()
        http {
            authorizeExchange {
                authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.DEFERRED_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.NOTIFICATION_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWKS, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWT_ISSUER, permitAll)
                authorize(MetaDataApi.PUBLIC_KEYS, permitAll)
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

            val dPoPProperties = ref<DPoPConfigurationProperties>()

            val dPoPTokenConverter = ServerDPoPAuthenticationTokenAuthenticationConverter()
            val dPoPEntryPoint = DPoPTokenServerAuthenticationEntryPoint(dPoPProperties.realm)

            val bearerTokenConverter = ServerBearerTokenAuthenticationConverter()
            val bearerTokenEntryPoint = BearerTokenServerAuthenticationEntryPoint()

            exceptionHandling {
                authenticationEntryPoint = DelegatingServerAuthenticationEntryPoint(
                    DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(dPoPTokenConverter),
                        dPoPEntryPoint,
                    ),
                    DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(bearerTokenConverter),
                        bearerTokenEntryPoint,
                    ),
                ).apply {
                    setDefaultEntryPoint(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
                }

                accessDeniedHandler = ServerWebExchangeDelegatingServerAccessDeniedHandler(
                    ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(dPoPTokenConverter),
                        DPoPTokenServerAccessDeniedHandler(dPoPProperties.realm),
                    ),
                    ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(bearerTokenConverter),
                        BearerTokenServerAccessDeniedHandler(),
                    ),
                ).apply {
                    setDefaultAccessDeniedHandler(HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN))
                }
            }

            val introspectionProperties = ref<OAuth2ResourceServerProperties>()
            val introspector = SpringReactiveOpaqueTokenIntrospector(
                introspectionProperties.opaquetoken.introspectionUri,
                ref<WebClient>()
                    .mutate()
                    .defaultHeaders {
                        it.setBasicAuth(
                            introspectionProperties.opaquetoken.clientId,
                            introspectionProperties.opaquetoken.clientSecret,
                        )
                    }
                    .build(),
            )

            val dPoPFilter = run {
                val dPoPVerifier = DPoPProtectedResourceRequestVerifier(
                    dPoPProperties.jwsAlgorithms(),
                    dPoPProperties.proofMaxAge.toSeconds(),
                    DefaultDPoPSingleUseChecker(
                        dPoPProperties.proofMaxAge.toSeconds(),
                        dPoPProperties.cachePurgeInterval.toSeconds(),
                    ),
                )

                val authenticationManager = DPoPTokenReactiveAuthenticationManager(introspector, dPoPVerifier)

                AuthenticationWebFilter(authenticationManager).apply {
                    setServerAuthenticationConverter(dPoPTokenConverter)
                    setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler(dPoPEntryPoint))
                }
            }

            val bearerTokenFilter = run {
                val authenticationManager = OpaqueTokenReactiveAuthenticationManager(introspector)

                AuthenticationWebFilter(authenticationManager).apply {
                    setServerAuthenticationConverter(bearerTokenConverter)
                    setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler(bearerTokenEntryPoint))
                }
            }

            http.addFilterAt(dPoPFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            http.addFilterAfter(bearerTokenFilter, SecurityWebFiltersOrder.AUTHENTICATION)
        }
    }

    //
    // Other
    //
    bean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }
            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
}

private fun Environment.credentialResponseEncryption(): CredentialResponseEncryption {
    val isSupported = getProperty<Boolean>("issuer.credentialResponseEncryption.supported") ?: false
    return if (!isSupported) {
        CredentialResponseEncryption.NotSupported
    } else {
        val parameters = CredentialResponseEncryptionSupportedParameters(
            algorithmsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.algorithmsSupported",
                JWEAlgorithm::parse,
            ),
            methodsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.encryptionMethods",
                EncryptionMethod::parse,
            ),
        )
        val isRequired = getProperty<Boolean>("issuer.credentialResponseEncryption.required") ?: false
        if (!isRequired) {
            CredentialResponseEncryption.Optional(parameters)
        } else {
            CredentialResponseEncryption.Required(parameters)
        }
    }
}

private fun Environment.readRequiredUrl(key: String, removeTrailingSlash: Boolean = false): HttpsUrl =
    getRequiredProperty(key)
        .let { url ->
            fun String.normalize() =
                if (removeTrailingSlash) {
                    this.removeSuffix("/")
                } else {
                    this
                }

            fun String.toHttpsUrl(): HttpsUrl = HttpsUrl.of(this) ?: HttpsUrl.unsafe(this)

            url.normalize().toHttpsUrl()
        }

private fun <T> Environment.readNonEmptySet(key: String, f: (String) -> T?): NonEmptySet<T> {
    val nonEmptySet = getRequiredProperty<MutableSet<String>>(key)
        .mapNotNull(f)
        .toNonEmptySetOrNull()
    return checkNotNull(nonEmptySet) { "Missing or incorrect values values for key `$key`" }
}

private fun HttpsUrl.appendPath(path: String): HttpsUrl =
    HttpsUrl.unsafe(
        UriComponentsBuilder.fromHttpUrl(externalForm)
            .path(path)
            .build()
            .toUriString(),
    )

/**
 * Configuration properties for Keycloak.
 */
@ConfigurationProperties("keycloak")
data class KeycloakConfigurationProperties(
    val serverUrl: URL,
    val authenticationRealm: String,
    val clientId: String,
    val username: String,
    val password: String,
    val userRealm: String,
) {
    init {
        require(authenticationRealm.isNotBlank()) { "'keycloak.authentication-realm' cannot be blank" }
        require(clientId.isNotBlank()) { "'keycloak.client-id' cannot be blank" }
        require(username.isNotBlank()) { "'keycloak.username' cannot be blank" }
        require(password.isNotBlank()) { "'keycloak.password' cannot be blank" }
        require(userRealm.isNotBlank()) { "'keycloak.user-realm' cannot be blank" }
    }
}

fun BeanDefinitionDsl.initializer(): ApplicationContextInitializer<GenericApplicationContext> =
    ApplicationContextInitializer<GenericApplicationContext> { initialize(it) }

@SpringBootApplication
@EnableConfigurationProperties(value = [DPoPConfigurationProperties::class, KeycloakConfigurationProperties::class])
class PidIssuerApplication

fun main(args: Array<String>) {
    runApplication<PidIssuerApplication>(*args) {
        addInitializers(beans(Clock.systemDefaultZone()).initializer())
    }
}
