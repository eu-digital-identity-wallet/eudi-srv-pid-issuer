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
package eu.europa.ec.eudi.pidissuer

import arrow.core.toNonEmptyListOrNull
import arrow.core.toNonEmptySetOrThrow
import com.eygraber.uri.Uri
import eu.europa.ec.eudi.pidissuer.adapter.input.scheduler.CredentialRevocationJob
import eu.europa.ec.eudi.pidissuer.adapter.input.web.*
import eu.europa.ec.eudi.pidissuer.adapter.input.web.csrf.CsrfTokenSubscriberWebFilter
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.EncryptCredentialResponseNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.EncryptDeferredResponseNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.GenerateSignedMetadataWithNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.nonce.DecryptNonceWithNimbusAndVerify
import eu.europa.ec.eudi.pidissuer.adapter.out.nonce.GenerateNonceAndEncryptWithNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryDeferredCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.R2dbcIssuedCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.qr.DefaultGenerateQrCode
import eu.europa.ec.eudi.pidissuer.adapter.out.status.GenerateStatusListTokenWithExternalService
import eu.europa.ec.eudi.pidissuer.adapter.out.status.GetStatusListTokenWithStatium
import eu.europa.ec.eudi.pidissuer.adapter.out.status.MarkStatusAsRevokedWithExternalService
import eu.europa.ec.eudi.pidissuer.adapter.out.webclient.KtorHttpClients
import eu.europa.ec.eudi.pidissuer.adapter.out.webclient.WebClients
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.asDeferred
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.MarkStatusAsRevoked
import eu.europa.ec.eudi.sdjwt.vc.Vct
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.TimeZone
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.Ordered
import org.springframework.core.env.getRequiredProperty
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.scheduling.annotation.SchedulingConfigurer
import java.net.URI
import java.security.KeyStore
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

val log = LoggerFactory.getLogger(PidIssuerApplication::class.java)

fun beans(
    clock: Clock,
    timeZone: TimeZone,
) = BeanRegistrarDsl {
    val issuerPublicUrl = env.readRequiredUrl("issuer.publicUrl", removeTrailingSlash = true)
    val issuerKeystore: KeyStore by lazy { keystore(env) }
    val getIssuerSigningKey = loadOrGenerateIssuerSigningKey(clock, env, issuerPublicUrl) { issuerKeystore }

    registerBean { env.dPoPConfigurationProperties() }
    registerBean(lazyInit = true) { loadOrGenerateAccessCertificate(env) { issuerKeystore } }
    registerBean { clock }
    registerBean { timeZone }
    registerBean { env.httpProxy() }
    registerBean { WebClients(bean(), secure = "insecure" !in env.activeProfiles) }
    registerBean { trustValidatorService(env, bean()) }
    registerBean { DefaultGenerateQrCode() }
    registerBean { HandleNotificationRequest(bean()) }
    registerBean {
        val cNonceExpiresIn = env.duration("issuer.cnonce.expiration") ?: 5.minutes
        HandleNonceRequest(clock, cNonceExpiresIn, bean())
    }
    registerBean(lazyInit = true) {
        val signedMetadataIssuer =
            env
                .getProperty("issuer.signed-metadata.issuer")
                ?.takeIf { it.isNotBlank() }
                ?.trim()
                ?.let { requireNotNull(HttpsUrl.of(it)) { "'issuer.signed-metadata.issuer' is not a valid HttpsUrl" } }
                ?: issuerPublicUrl

        GenerateSignedMetadataWithNimbus(
            clock = bean(),
            signedMetadataIssuer = signedMetadataIssuer,
            credentialIssuerId = bean<CredentialIssuerMetaData>().id,
            accessCertificate = bean(),
        )
    }
    registerBean<GetStatusListTokenStatus> {
        val httpClient = KtorHttpClients(bean(), secure = "insecure" !in env.activeProfiles)
        GetStatusListTokenWithStatium(
            httpClient,
            clock = clock,
            allowedClockSkew = 5.seconds,
        )
    }
    registerBean {
        RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = bean(),
            getNonExpiredIssuedCredentials = bean(),
            getStatusListTokenStatus = bean(),
            markStatusAsRevoked = bean(),
            deleteIssuedCredential = bean(),
        )
    }
    registerBean { CredentialRevocationJob(bean()) }
    registerBean {
        val cron = env.getProperty("issuer.revocationJob.cron", "0 0 */8 * * *")
        SchedulingConfigurer { taskRegistrar ->
            taskRegistrar.addCronTask({
                runBlocking {
                    bean<CredentialRevocationJob>().run()
                }
            }, cron)
        }
    }

    registerBean<AllocateStatus> {
        val serviceUrl = URI.create(env.getRequiredProperty("issuer.statusList.service.generate-uri")).toURL()
        GenerateStatusListTokenWithExternalService(
            webClient = bean(),
            serviceUrl = serviceUrl,
            apiKey = env.getRequiredProperty("issuer.statusList.service.apiKey"),
            timeZone = timeZone,
        )
    }

    registerBean<MarkStatusAsRevoked> {
        val serviceUrl = URI.create(env.getRequiredProperty("issuer.statusList.service.revoke-uri")).toURL()
        MarkStatusAsRevokedWithExternalService(
            webClient = bean(),
            serviceUrl = serviceUrl,
            apiKey = env.getRequiredProperty("issuer.statusList.service.apiKey"),
        )
    }

    //
    // Encryption of credential response
    //
    registerBean(lazyInit = true) {
        EncryptDeferredResponseNimbus(bean<CredentialIssuerMetaData>().id, clock)
    }
    registerBean(lazyInit = true) {
        EncryptCredentialResponseNimbus(bean<CredentialIssuerMetaData>().id, clock)
    }

    //
    // Nonce
    //
    registerBean { loadNonceEncryptionKey(env) { issuerKeystore } }
    registerBean { GenerateNonceAndEncryptWithNimbus(issuerPublicUrl, bean()) }
    registerBean { DecryptNonceWithNimbusAndVerify(issuerPublicUrl, bean()) }

    //
    // Credentials
    //
    registerBean { GenerateNotificationId.Random }
    registerBean { R2dbcIssuedCredentialRepository(bean()) }
    registerBean { bean<R2dbcIssuedCredentialRepository>().storeIssuedCredential }
    registerBean { bean<R2dbcIssuedCredentialRepository>().loadIssuedCredentialsByNotificationId }
    registerBean { bean<R2dbcIssuedCredentialRepository>().getNonExpiredIssuedCredentials }
    registerBean { bean<R2dbcIssuedCredentialRepository>().deleteExpiredIssuedCredentials }
    registerBean { bean<R2dbcIssuedCredentialRepository>().deleteIssuedCredential }

    //
    // Deferred Credentials
    //
    with(InMemoryDeferredCredentialRepository(mutableMapOf(), clock)) {
        registerBean { GenerateTransactionId.Random }
        registerBean { storeDeferredCredential }
        registerBean { loadDeferredCredentialByTransactionId }
    }

    //
    // Specific Issuers
    //

    registerBean {
        getPidDataFromKeyCloak(clock, timeZone, env, webClient = bean())
    }
    registerBean {
        val ctx =
            IssuerFactory.Ctx(
                clock,
                timeZone,
                env,
                credentialIssuerId = issuerPublicUrl,
                validateProof = validateProof(issuerPublicUrl, bean(), bean()),
                storeIssuedCredential = bean(),
                allocateStatus = bean(),
                generateNotificationId = bean(),
            )
        val attestationIssuers =
            context(ctx) {
                buildList {
                    if (env.getBoolean("issuer.pid.mso_mdoc.enabled") ?: true) {
                        val issueMsoMdocPid =
                            IssuerFactory.pidInMdoc(
                                issuerSigningKey = getIssuerSigningKey("issuer.pid.mso_mdoc.signing-key"),
                                getAttestationAttributes = bean(),
                            )
                        add(issueMsoMdocPid)
                        add(issueMsoMdocPid.asDeferred(bean(), bean(), clock))
                    }

                    if (env.getBoolean("issuer.pid.sd_jwt_vc.enabled") ?: true) {
                        val issueSdJwtVcPid =
                            IssuerFactory.pidInSdJwtVc(
                                issuerSigningKey = getIssuerSigningKey("issuer.pid.sd_jwt_vc.signing-key"),
                                getAttestationAttributes = bean(),
                            )
                        add(issueSdJwtVcPid)
                        add(issueSdJwtVcPid.asDeferred(bean(), bean(), clock))
                    }

                    if (env.getBoolean("issuer.mdl.enabled", true)) {
                        val mdlIssuer = IssuerFactory.mdl(getIssuerSigningKey("issuer.mdl.signing-key"))
                        add(mdlIssuer)
                        add(mdlIssuer.asDeferred(bean(), bean(), clock))
                    }
                    if (env.getBoolean("issuer.learningCredential.enabled") ?: true) {
                        val issueLearningCredential =
                            IssuerFactory.learningCredentialInSdJwtVc(
                                issuerSigningKey = getIssuerSigningKey("issuer.learningCredential.signing-key"),
                                getPidData = bean(),
                            )
                        add(issueLearningCredential)
                        add(issueLearningCredential.asDeferred(bean(), bean(), bean()))
                    }
                }.toNonEmptyListOrNull()
            }
        checkNotNull(attestationIssuers) { "At least one credential issuer must be configured" }

        val preferredClientStatusPeriod =
            bean<IssuerMetadataProperties>().preferredClientStatusPeriod.toKotlinDuration()

        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = issuerPublicUrl.appendPath(WalletApi.CREDENTIAL_ENDPOINT),
            deferredCredentialEndpoint = issuerPublicUrl.appendPath(WalletApi.DEFERRED_ENDPOINT),
            notificationEndpoint = issuerPublicUrl.appendPath(WalletApi.NOTIFICATION_ENDPOINT),
            nonceEndpoint = issuerPublicUrl.appendPath(WalletApi.NONCE_ENDPOINT),
            authorizationServers = listOf(env.readRequiredUrl("issuer.authorizationServer.publicUrl")),
            credentialRequestEncryption = env.credentialRequestEncryption { issuerKeystore },
            credentialResponseEncryption = env.credentialResponseEncryption(),
            attestationIssuers = attestationIssuers,
            batchCredentialIssuance = env.batchCredentialIssuance(),
            display =
                bean<IssuerMetadataProperties>()
                    .display
                    .map { display ->
                        CredentialIssuerDisplay(
                            name = display.name,
                            locale = display.locale?.let { Locale.forLanguageTag(it) },
                            logo = display.logo?.let { ImageUri(it.uri, it.alternativeText) },
                        )
                    },
            preferredClientStatusPeriod = PreferredClientStatusPeriod(preferredClientStatusPeriod),
        )
    }

    //
    // In Ports (use cases)
    //
    registerBean {
        GetCredentialIssuerMetaData(bean(), bean())
    }
    registerBean {
        IssueCredential(
            credentialIssuerMetadata = bean(),
            encryptCredentialResponse = bean(),
            clock = bean(),
        )
    }
    registerBean {
        GetDeferredCredential(bean(), bean(), bean())
    }
    registerBean {
        val defaultCredentialOfferUri = Uri.parse(env.getRequiredProperty("issuer.credentialOffer.defaultUri"))
        val allowedSchemes =
            env
                .getRequiredProperty<Set<String>>("issuer.credentialOffer.allowedSchemes")
                .map { SupportedCredentialOfferUriScheme.of(it) }
                .toNonEmptySetOrThrow()
        CreateCredentialsOffer(bean(), defaultCredentialOfferUri, allowedSchemes)
    }

    registerBean {
        GetProtectedResourceMetadata(
            credentialIssuerMetadata = bean(),
            dPoPConfigurationProperties = bean(),
        )
    }

    //
    // Routes
    //
    registerBean {
        val typeMetadata =
            bean<SdJwtVcProperties>()
                .typeMetadata
                .associateBy { Vct(it.vct) }
                .mapValues { it.value.resource }
        val metaDataApi = MetaDataApi(bean(), bean(), typeMetadata, bean())
        val walletApi = WalletApi(bean(), bean(), bean(), bean())
        val issuerUi = IssuerUi(bean(), bean(), bean())
        val issuerApi = IssuerApi(bean())
        metaDataApi.route
            .and(walletApi.route)
            .and(issuerUi.router)
            .and(issuerApi.router)
    }

    //
    // Security
    //

    // UI Security
    registerBean(order = Ordered.HIGHEST_PRECEDENCE) {
        configureUiSecurity(env, bean())
    }
    registerBean<CsrfTokenSubscriberWebFilter>()

    // API Security
    registerBean(order = Ordered.HIGHEST_PRECEDENCE + 10) {
        configureApiSecurity(
            http = bean(),
            metadata = bean(),
            oAuth2ResourceServerProperties = bean(),
            dPoPConfigurationProperties = bean(),
            webClient = bean(),
            env = env,
            clock = clock,
            verifyNonce = bean(),
            generateNonce = bean(),
        )
    }

    //
    // Other
    //
    registerBean {
        CodecCustomizer {
            val json =
                Json {
                    explicitNulls = false
                    ignoreUnknownKeys = true
                }
            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
}
