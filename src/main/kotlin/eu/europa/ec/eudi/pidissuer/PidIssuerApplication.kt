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
import arrow.core.recover
import arrow.core.some
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.*
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.CredentialRequestFactory
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.DecryptCNonceWithNimbusAndVerify
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.DefaultResolveCredentialRequestByCredentialIdentifier
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.GenerateCNonceAndEncryptWithNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.*
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.*
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryDeferredCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryIssuedCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.adapter.out.qr.DefaultGenerateQrCode
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.status.GenerateStatusListTokenWithExternalService
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.asDeferred
import eu.europa.ec.eudi.pidissuer.port.out.jose.GenerateSignedMetadata
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.status.GenerateStatusListToken
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import jakarta.ws.rs.client.Client
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.runBlocking
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
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.FileSystemResource
import org.springframework.core.io.Resource
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
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
import java.net.URI
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.util.*
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration
import kotlin.time.toKotlinDuration

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

fun beans(clock: Clock) = beans {
    val issuerPublicUrl = env.readRequiredUrl("issuer.publicUrl", removeTrailingSlash = true)
    val enableMobileDrivingLicence = env.getProperty("issuer.mdl.enabled", true)
    val enableMsoMdocPid = env.getProperty<Boolean>("issuer.pid.mso_mdoc.enabled") ?: true
    val enableSdJwtVcPid = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.enabled") ?: true
    val credentialsOfferUri = env.getRequiredProperty("issuer.credentialOffer.uri")
    val enableStatusList = env.getProperty<Boolean>("issuer.statusList.enabled") ?: false

    //
    // Signing key
    //
    bean(isLazyInit = true) {
        val signingKey = when (env.getProperty<KeyOption>("issuer.signing-key")) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random signing key and self-signed certificate for issuance")
                val key = ECKeyGenerator(Curve.P_256).keyID("issuer-kid-0").generate()
                val certificate = X509CertificateUtils.generateSelfSigned(
                    Issuer(issuerPublicUrl.value.host),
                    Date.from(clock.instant()),
                    Date.from(clock.instant() + 365.days.toJavaDuration()),
                    key.toECPublicKey(),
                    key.toECPrivateKey(),
                )
                ECKey.Builder(key)
                    .x509CertChain(listOf(Base64.encode(certificate.encoded)))
                    .build()
            }

            KeyOption.LoadFromKeystore -> {
                log.info("Loading signing key and certificate for issuance from keystore")
                loadJwkFromKeystore(env, "issuer.signing-key")
            }
        }
        require(signingKey is ECKey) { "Only ECKeys are supported for signing" }
        IssuerSigningKey(signingKey)
    }

    //
    // CNonce encryption key
    //
    bean(name = "cnonce-encryption-key") {
        val encryptionKey = when (env.getProperty<KeyOption>("issuer.cnonce.encryption-key")) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random encryption key for CNonce")
                RSAKeyGenerator(4096, false).generate()
            }
            KeyOption.LoadFromKeystore -> {
                log.info("Loading CNonce encryption key from keystore")
                loadJwkFromKeystore(env, "issuer.cnonce.encryption-key")
            }
        }
        require(encryptionKey is RSAKey) { "Only RSAKeys are supported for encryption" }
        encryptionKey
    }

    //
    // Signed metadata signing key
    //
    bean(isLazyInit = true) {
        val key = when (env.getProperty<KeyOption>("issuer.metadata.signed-metadata.signing-key")) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random signing key for metadata")
                ECKeyGenerator(Curve.P_256)
                    .keyID("issuer-kid-1")
                    .keyUse(KeyUse.SIGNATURE)
                    .generate()
            }

            KeyOption.LoadFromKeystore -> {
                log.info("Loading signing key and certificate for metadata from keystore")
                loadJwkFromKeystore(env, "issuer.metadata.signed-metadata.signing-key")
            }
        }

        val issuer = env.getProperty("issuer.metadata.signed-metadata.issuer")
            ?.takeIf { it.isNotBlank() }
            ?.trim()
            ?: issuerPublicUrl.externalForm

        MetadataSigningKey(key = key, issuer = issuer)
    }

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
        KeycloakConfigurationProperties(
            env.getRequiredProperty("issuer.keycloak.server-url", URL::class.java),
            env.getRequiredProperty("issuer.keycloak.authentication-realm"),
            env.getRequiredProperty("issuer.keycloak.client-id"),
            env.getRequiredProperty("issuer.keycloak.username"),
            env.getRequiredProperty("issuer.keycloak.password"),
            env.getRequiredProperty("issuer.keycloak.user-realm"),
        )
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
            issuerCountry = env.getRequiredProperty("issuer.pid.issuingCountry").let(::IsoCountry),
            issuingJurisdiction = env.getProperty("issuer.pid.issuingJurisdiction"),
            clock = clock,
            keycloak = keycloak,
            userRealm = keycloakProperties.userRealm,
        )
    }
    bean<EncodePidInCbor>(isLazyInit = true) {
        log.info("Using internal encoder to encode PID in CBOR")
        val issuerSigningKey = ref<IssuerSigningKey>()
        val duration = env.duration("issuer.pid.mso_mdoc.encoder.duration")?.toKotlinDuration() ?: 30.days
        DefaultEncodePidInCbor(clock, issuerSigningKey, duration)
    }

    bean {
        GetMobileDrivingLicenceDataMock()
    }
    bean<EncodeMobileDrivingLicenceInCbor>(isLazyInit = true) {
        log.info("Using internal encoder to encode mDL in CBOR")
        val issuerSigningKey = ref<IssuerSigningKey>()
        val duration = env.duration("issuer.mdl.mso_mdoc.encoder.duration")?.toKotlinDuration() ?: 5.days
        DefaultEncodeMobileDrivingLicenceInCbor(clock, issuerSigningKey, duration)
    }

    bean(::DefaultGenerateQrCode)
    bean(::HandleNotificationRequest)
    bean {
        val cNonceExpiresIn = env.duration("issuer.cnonce.expiration") ?: Duration.ofMinutes(5L)
        HandleNonceRequest(clock, cNonceExpiresIn, ref())
    }
    bean {
        val resolvers = buildMap<CredentialIdentifier, CredentialRequestFactory> {
            if (enableMobileDrivingLicence) {
                this[CredentialIdentifier(MobileDrivingLicenceV1Scope.value)] =
                    { unvalidatedProofs, requestedResponseEncryption ->
                        MsoMdocCredentialRequest(
                            unvalidatedProofs = unvalidatedProofs,
                            credentialResponseEncryption = requestedResponseEncryption,
                            docType = MobileDrivingLicenceV1.docType,
                        )
                    }
            }

            if (enableMsoMdocPid) {
                this[CredentialIdentifier(PidMsoMdocScope.value)] =
                    { unvalidatedProofs, requestedResponseEncryption ->
                        MsoMdocCredentialRequest(
                            unvalidatedProofs = unvalidatedProofs,
                            credentialResponseEncryption = requestedResponseEncryption,
                            docType = PidMsoMdocV1.docType,
                        )
                    }
            }

            if (enableSdJwtVcPid) {
                val signingAlgorithm = ref<IssuerSigningKey>().signingAlgorithm
                pidSdJwtVcV1(signingAlgorithm).let { sdJwtVcPid ->
                    this[CredentialIdentifier(PidSdJwtVcScope.value)] =
                        { unvalidatedProofs, requestedResponseEncryption ->
                            SdJwtVcCredentialRequest(
                                unvalidatedProofs = unvalidatedProofs,
                                credentialResponseEncryption = requestedResponseEncryption,
                                type = sdJwtVcPid.type,
                            )
                        }
                }
            }
        }

        DefaultResolveCredentialRequestByCredentialIdentifier(resolvers)
    }
    bean(isLazyInit = true) {
        GenerateSignedMetadataWithNimbus(
            clock = ref(),
            credentialIssuerId = ref<CredentialIssuerMetaData>().id,
            signingKey = ref(),
        )
    }
    if (enableStatusList) {
        bean<GenerateStatusListToken> {
            val serviceUrl = URL(env.getRequiredProperty("issuer.statusList.service.uri"))
            log.info("Token Status List support enabled. Service URL: ${serviceUrl.toExternalForm()}")
            GenerateStatusListTokenWithExternalService(
                webClient = ref(),
                serviceUrl = serviceUrl,
                apiKey = env.getRequiredProperty("issuer.statusList.service.apiKey"),
            )
        }
    }

    //
    // Encryption of credential response
    //
    bean(isLazyInit = true) {
        EncryptDeferredResponseNimbus(ref<CredentialIssuerMetaData>().id, clock)
    }
    bean(isLazyInit = true) {
        EncryptCredentialResponseNimbus(ref<CredentialIssuerMetaData>().id, clock)
    }
    //
    // CNonce
    //
    bean { GenerateCNonceAndEncryptWithNimbus(issuerPublicUrl, ref<RSAKey>("cnonce-encryption-key")) }
    bean { DecryptCNonceWithNimbusAndVerify(issuerPublicUrl, ref<RSAKey>("cnonce-encryption-key")) }

    //
    // Credentials
    //
    with(InMemoryIssuedCredentialRepository()) {
        bean { GenerateNotificationId.Random }
        bean { storeIssuedCredentials }
        bean { loadIssuedCredentialsByNotificationId }
    }

    //
    // Deferred Credentials
    //
    with(InMemoryDeferredCredentialRepository(mutableMapOf())) {
        bean { GenerateTransactionId.Random }
        bean { storeDeferredCredential }
        bean { loadDeferredCredentialByTransactionId }
    }

    //
    // Specific Issuers
    //
    bean { ValidateJwtProof(issuerPublicUrl) }
    bean { DefaultExtractJwkFromCredentialKey }
    bean { ValidateProofs(ref(), ref(), ref()) }
    bean {
        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = issuerPublicUrl.appendPath(WalletApi.CREDENTIAL_ENDPOINT),
            deferredCredentialEndpoint = issuerPublicUrl.appendPath(WalletApi.DEFERRED_ENDPOINT),
            notificationEndpoint = issuerPublicUrl.appendPath(WalletApi.NOTIFICATION_ENDPOINT),
            nonceEndpoint = issuerPublicUrl.appendPath(WalletApi.NONCE_ENDPOINT),
            authorizationServers = listOf(env.readRequiredUrl("issuer.authorizationServer.publicUrl")),
            credentialResponseEncryption = env.credentialResponseEncryption(),
            specificCredentialIssuers = buildList {
                if (enableMsoMdocPid) {
                    val issueMsoMdocPid = IssueMsoMdocPid(
                        getPidData = ref(),
                        encodePidInCbor = ref(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.mso_mdoc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        clock = clock,
                        storeIssuedCredentials = ref(),
                        validateProofs = ref(),
                    )
                    add(issueMsoMdocPid)
                }

                if (enableSdJwtVcPid) {
                    val expiresIn = env.duration("issuer.pid.sd_jwt_vc.duration") ?: Duration.ofDays(30L)
                    val notUseBefore = env.duration("issuer.pid.sd_jwt_vc.notUseBefore")

                    val issuerSigningKey = ref<IssuerSigningKey>()
                    val issueSdJwtVcPid = IssueSdJwtVcPid(
                        hashAlgorithm = HashAlgorithm.SHA3_256,
                        issuerSigningKey = issuerSigningKey,
                        getPidData = ref(),
                        clock = clock,
                        credentialIssuerId = issuerPublicUrl,
                        calculateExpiresAt = { iat -> (iat + expiresIn).toInstant() },
                        calculateNotUseBefore = notUseBefore?.let { duration ->
                            {
                                    iat ->
                                iat.plusSeconds(duration.seconds).toInstant()
                            }
                        },
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        storeIssuedCredentials = ref(),
                        validateProofs = ref(),
                        generateStatusListToken = provider<GenerateStatusListToken>().ifAvailable,
                    )

                    val deferred = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.deferred") ?: false
                    add(
                        if (deferred) issueSdJwtVcPid.asDeferred(ref(), ref())
                        else issueSdJwtVcPid,
                    )
                }

                if (enableMobileDrivingLicence) {
                    val mdlIssuer = IssueMobileDrivingLicence(
                        getMobileDrivingLicenceData = ref(),
                        encodeMobileDrivingLicenceInCbor = ref(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.mdl.notifications.enabled") ?: true,
                        generateNotificationId = ref(),
                        clock = clock,
                        storeIssuedCredentials = ref(),
                        validateProofs = ref(),
                    )
                    add(mdlIssuer)
                }
            },
            batchCredentialIssuance = run {
                val enabled = env.getProperty<Boolean>("issuer.credentialEndpoint.batchIssuance.enabled") ?: true
                if (enabled) {
                    val batchSize = env.getProperty<Int>("issuer.credentialEndpoint.batchIssuance.batchSize") ?: 10
                    BatchCredentialIssuance.Supported(batchSize)
                } else {
                    BatchCredentialIssuance.NotSupported
                }
            },
            display = ref<IssuerMetadataProperties>().display
                .map { display ->
                    CredentialIssuerDisplay(
                        name = display.name,
                        locale = display.locale?.let { Locale.forLanguageTag(it) },
                        logo = display.logo?.let { ImageUri(it.uri, it.alternativeText) },
                    )
                },
        )
    }

    //
    // In Ports (use cases)
    //
    bean {
        val enableSignedMetadata = env.getProperty<Boolean>("issuer.metadata.signed-metadata.enabled") ?: true
        val generateSignedMetadata = if (enableSignedMetadata) ref<GenerateSignedMetadata>() else null
        GetCredentialIssuerMetaData(ref(), generateSignedMetadata)
    }
    bean {
        IssueCredential(
            credentialIssuerMetadata = ref(),
            resolveCredentialRequestByCredentialIdentifier = ref(),
            encryptCredentialResponse = ref(),
        )
    }
    bean {
        GetDeferredCredential(ref(), ref())
    }
    bean {
        CreateCredentialsOffer(ref(), credentialsOfferUri)
    }

    //
    // Routes
    //
    bean {
        val metaDataApi = MetaDataApi(ref(), ref())
        val walletApi = WalletApi(ref(), ref(), ref(), ref(), ref())
        val issuerUi = IssuerUi(credentialsOfferUri, ref(), ref(), ref())
        val issuerApi = IssuerApi(ref())
        metaDataApi.route.and(walletApi.route).and(issuerUi.router).and(issuerApi.router)
    }

    //
    // DPoP Nonce
    //
    if (env.getProperty("issuer.dpop.nonce.enabled", Boolean::class.java, false)) {
        val dpopNonceExpiresIn = env.duration("issuer.dpop.nonce.expiration") ?: Duration.ofMinutes(5L)
        with(InMemoryDPoPNonceRepository(clock, dpopNonceExpiresIn)) {
            bean { DPoPNoncePolicy.Enforcing(loadActiveDPoPNonce, generateDPoPNonce) }
            bean {
                object {
                    @Scheduled(fixedRate = 1L, timeUnit = TimeUnit.MINUTES)
                    suspend fun cleanup() {
                        cleanupInactiveDPoPNonce()
                    }
                }
            }
        }
        bean(::DPoPNonceWebFilter)
    } else {
        bean { DPoPNoncePolicy.Disabled }
    }

    //
    // Security
    //
    bean {
        val algorithms = runCatching {
            runBlocking {
                val client = ref<WebClient>()
                val metadata = client.get()
                    .uri(env.getRequiredProperty("issuer.authorizationServer.metadata"))
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(String::class.java)
                    .timeout(Duration.ofSeconds(5L))
                    .awaitSingle()
                OIDCProviderMetadata.parse(metadata)
            }.dPoPJWSAlgs?.toSet() ?: emptySet()
        }.getOrElse {
            log.warn("Unable to fetch Authorization Server metadata. DPoP support will be disabled.", it)
            emptySet()
        }.also {
            if (it.isEmpty()) log.warn("DPoP support will not be enabled. Authorization Server does not support DPoP.")
            else log.info("DPoP support will be enabled. Supported algorithms: $it")
        }
        val proofMaxAge = env.duration("issuer.dpop.proof-max-age") ?: Duration.ofMinutes(1L)
        val cachePurgeInterval = env.duration("issuer.dpop.cache-purge-interval") ?: Duration.ofMinutes(10L)
        val realm = env.getProperty("issuer.dpop.realm")?.takeIf { it.isNotBlank() }

        DPoPConfigurationProperties(algorithms, proofMaxAge, cachePurgeInterval, realm)
    }
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
                authorize(WalletApi.NONCE_ENDPOINT, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWT_VC_ISSUER, permitAll)
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
            val enableDPoP = dPoPProperties.algorithms.isNotEmpty()

            val dPoPTokenConverter by lazy { ServerDPoPAuthenticationTokenAuthenticationConverter() }
            val dPoPEntryPoint by lazy { DPoPTokenServerAuthenticationEntryPoint(dPoPProperties.realm, ref()) }

            val bearerTokenConverter = ServerBearerTokenAuthenticationConverter()
            val bearerTokenEntryPoint = BearerTokenServerAuthenticationEntryPoint()

            exceptionHandling {
                authenticationEntryPoint = DelegatingServerAuthenticationEntryPoint(
                    buildList {
                        if (enableDPoP) {
                            add(
                                DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                                    AuthenticationConverterServerWebExchangeMatcher(dPoPTokenConverter),
                                    dPoPEntryPoint,
                                ),
                            )
                        }

                        add(
                            DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                                AuthenticationConverterServerWebExchangeMatcher(bearerTokenConverter),
                                bearerTokenEntryPoint,
                            ),
                        )
                    },
                ).apply {
                    setDefaultEntryPoint(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
                }

                accessDeniedHandler = ServerWebExchangeDelegatingServerAccessDeniedHandler(
                    buildList {
                        if (enableDPoP) {
                            ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                                AuthenticationConverterServerWebExchangeMatcher(dPoPTokenConverter),
                                DPoPTokenServerAccessDeniedHandler(dPoPProperties.realm),
                            )
                        }

                        add(
                            ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                                AuthenticationConverterServerWebExchangeMatcher(bearerTokenConverter),
                                BearerTokenServerAccessDeniedHandler(),
                            ),
                        )
                    },
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

            if (enableDPoP) {
                val dPoPFilter = run {
                    val dPoPVerifier = DPoPProtectedResourceRequestVerifier(
                        dPoPProperties.algorithms,
                        dPoPProperties.proofMaxAge.toSeconds(),
                        DefaultDPoPSingleUseChecker(
                            dPoPProperties.proofMaxAge.toSeconds(),
                            dPoPProperties.cachePurgeInterval.toSeconds(),
                        ),
                    )

                    val authenticationManager = DPoPTokenReactiveAuthenticationManager(introspector, dPoPVerifier, ref())

                    AuthenticationWebFilter(authenticationManager).apply {
                        setServerAuthenticationConverter(ServerDPoPAuthenticationTokenAuthenticationConverter())
                        setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler(dPoPEntryPoint))
                    }
                }

                http.addFilterAt(dPoPFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            }

            val bearerTokenFilter = run {
                val authenticationManager = OpaqueTokenReactiveAuthenticationManager(introspector)

                AuthenticationWebFilter(authenticationManager).apply {
                    setServerAuthenticationConverter(ServerBearerTokenAuthenticationConverter())
                    setAuthenticationFailureHandler(
                        ServerAuthenticationEntryPointFailureHandler(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)),
                    )
                }
            }
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

private fun Environment.duration(key: String): Duration? =
    getProperty(key)?.let { Duration.parse(it) }?.takeUnless { it.isNegative || it.isZero }

private fun HttpsUrl.appendPath(path: String): HttpsUrl =
    HttpsUrl.unsafe(
        UriComponentsBuilder.fromUriString(externalForm)
            .path(path)
            .build()
            .toUriString(),
    )

private const val keystoreDefaultLocation = "/keystore.jks"

/**
 * Loads a key pair alongside its associated certificate chain as a JWK.
 *
 * This method expects to find the following properties in the provided [environment].
 * - [prefix].keystore -> location of the keystore as a Spring [Resource] URL
 * - [prefix].keystore.type -> type of the keystore, e.g. JKS
 * - [prefix].keystore.password -> password used to open the keystore
 * - [prefix].alias -> alias of the key pair to load
 * - [prefix].password -> password of the key pair
 *
 * In case no keystore is found in the configured location, this methods tries to find a keystore at the location `/keystore.jks`.
 */
@Suppress("SameParameterValue")
private fun loadJwkFromKeystore(environment: Environment, prefix: String): JWK {
    fun property(property: String): String =
        when {
            prefix.isBlank() -> property
            prefix.endsWith(".") -> "$prefix$property"
            else -> "$prefix.$property"
        }

    fun JWK.withCertificateChain(chain: List<X509Certificate>): JWK {
        require(this.parsedX509CertChain.isNotEmpty()) { "jwk must have a leaf certificate" }
        require(chain.isNotEmpty()) { "chain cannot be empty" }
        require(this.parsedX509CertChain.first() == chain.first()) {
            "leaf certificate of provided chain does not match leaf certificate of jwk"
        }

        val encodedChain = chain.map { Base64.encode(it.encoded) }
        return when (this) {
            is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
            is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
            is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
            is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
            else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
        }
    }

    val keystoreResource = run {
        val keystoreLocation = environment.getRequiredProperty(property("keystore"))
        log.info("Will try to load Keystore from: '{}'", keystoreLocation)
        val keystoreResource = DefaultResourceLoader().getResource(keystoreLocation).some()
            .filter { it.exists() }
            .recover {
                log.warn(
                    "Could not find Keystore at '{}'. Fallback to '{}'",
                    keystoreLocation,
                    keystoreDefaultLocation,
                )
                FileSystemResource(keystoreDefaultLocation).some()
                    .filter { it.exists() }
                    .bind()
            }
            .getOrNull()
        checkNotNull(keystoreResource) { "Could not load Keystore either from '$keystoreLocation' or '$keystoreDefaultLocation'" }
    }

    val keystoreType = environment.getProperty(property("keystore.type"), KeyStore.getDefaultType())
    val keystorePassword = environment.getProperty(property("keystore.password"))?.takeIf { it.isNotBlank() }
    val keyAlias = environment.getRequiredProperty(property("alias"))
    val keyPassword = environment.getProperty(property("password"))?.takeIf { it.isNotBlank() }

    return keystoreResource.inputStream.use { inputStream ->
        val keystore = KeyStore.getInstance(keystoreType)
        keystore.load(inputStream, keystorePassword?.toCharArray())

        val jwk = JWK.load(keystore, keyAlias, keyPassword?.toCharArray())
        val chain = keystore.getCertificateChain(keyAlias).orEmpty()
            .map { certificate -> certificate as X509Certificate }
            .toList()

        when {
            chain.isNotEmpty() -> jwk.withCertificateChain(chain)
            else -> jwk
        }
    }
}

/**
 * Indicates whether a random key pairs should be generated, or a key pair should be loaded from a keystore.
 */
private enum class KeyOption {
    GenerateRandom,
    LoadFromKeystore,
}

/**
 * Configuration properties for Keycloak.
 */
data class KeycloakConfigurationProperties(
    val serverUrl: URL,
    val authenticationRealm: String,
    val clientId: String,
    val username: String,
    val password: String,
    val userRealm: String,
) {
    init {
        require(authenticationRealm.isNotBlank()) { "'authenticationRealm' cannot be blank" }
        require(clientId.isNotBlank()) { "'clientId' cannot be blank" }
        require(username.isNotBlank()) { "'username' cannot be blank" }
        require(password.isNotBlank()) { "'password' cannot be blank" }
        require(userRealm.isNotBlank()) { "'userRealm' cannot be blank" }
    }
}

/**
 * Configuration properties for Issuer metadata.
 */
@ConfigurationProperties("issuer.metadata")
private data class IssuerMetadataProperties(
    val display: List<DisplayProperties> = emptyList(),
) {
    data class DisplayProperties(
        val name: String? = null,
        val locale: String? = null,
        val logo: LogoProperties? = null,
    )

    data class LogoProperties(
        val uri: URI,
        val alternativeText: String? = null,
    )
}

fun BeanDefinitionDsl.initializer(): ApplicationContextInitializer<GenericApplicationContext> =
    ApplicationContextInitializer<GenericApplicationContext> { initialize(it) }

@SpringBootApplication
@EnableConfigurationProperties(IssuerMetadataProperties::class)
@EnableScheduling
class PidIssuerApplication

fun main(args: Array<String>) {
    runApplication<PidIssuerApplication>(*args) {
        addInitializers(beans(Clock.systemDefaultZone()).initializer())
    }
}
