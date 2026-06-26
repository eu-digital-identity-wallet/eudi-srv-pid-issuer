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

import arrow.core.NonEmptySet
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.learningcredential.IssueLearningCredential
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.IssueMobileDrivingLicence
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.MobileDrivingLicence
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.RandomMobileDrivingLicence
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid.*
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.SdJwtVcSerialization
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.*
import eu.europa.ec.eudi.pidissuer.adapter.out.proof.ValidateAttestationProof
import eu.europa.ec.eudi.pidissuer.adapter.out.proof.ValidateJwtProofWithKeyAttestation
import eu.europa.ec.eudi.pidissuer.adapter.out.proof.VerifyKeyAttestation
import eu.europa.ec.eudi.pidissuer.adapter.out.webclient.HttpProxy
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.nonce.VerifyNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedKeyAttestationIssuer
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import io.ktor.http.*
import kotlinx.datetime.TimeZone
import org.slf4j.LoggerFactory
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.env.getRequiredProperty
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

private val extensionLogger = LoggerFactory.getLogger("eu.europa.ec.eudi.pidissuer.IssuerEnvironmentExtensions")

internal fun credentialReusePolicy(
    env: Environment,
    prefix: String,
): CredentialReusePolicy {
    val enabled = env.getProperty<Boolean>("$prefix.reusePolicy.enabled") ?: false
    if (!enabled) return CredentialReusePolicy.None

    val type = env.getProperty("$prefix.reusePolicy.type") ?: "ArfAnnex2"
    return when (type) {
        "ArfAnnex2" -> {
            val options = mutableListOf<EudiReusePolicy>()
            var index = 0
            while (true) {
                val detailsStr = env.getPropertyOrEnvVariable("$prefix.reusePolicy.options[$index].details") ?: break
                val methods = detailsStr.split(",").map { it.trim() }.mapNotNull { EudiReusePolicyType.fromValue(it) }
                if (methods.isEmpty()) {
                    index++
                    continue
                }
                methods.mapTo(options) { method ->
                    when (method) {
                        EudiReusePolicyType.OnceOnly -> {
                            val batchSize =
                                env.getRequiredPropertyOrEnvVariable<Int>("$prefix.reusePolicy.options[$index].batchSize")
                            val reissueTriggerUnused =
                                env.getRequiredPropertyOrEnvVariable<Int>(
                                    "$prefix.reusePolicy.options[$index].reissueTriggerUnused",
                                )
                            EudiReusePolicy.OnceOnly(batchSize, reissueTriggerUnused)
                        }

                        EudiReusePolicyType.LimitedTime -> {
                            val reissueTriggerLifetimeLeft =
                                env
                                    .getRequiredPropertyOrEnvVariable<Long>(
                                        "$prefix.reusePolicy.options[$index].reissueTriggerLifetimeLeft",
                                    ).seconds
                            EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft)
                        }

                        EudiReusePolicyType.RotatingBatch -> {
                            val batchSize =
                                env.getRequiredPropertyOrEnvVariable<Int>("$prefix.reusePolicy.options[$index].batchSize")
                            val reissueTriggerLifetimeLeft =
                                env
                                    .getRequiredPropertyOrEnvVariable<Long>(
                                        "$prefix.reusePolicy.options[$index].reissueTriggerLifetimeLeft",
                                    ).seconds
                            EudiReusePolicy.RotatingBatch(batchSize, reissueTriggerLifetimeLeft)
                        }

                        EudiReusePolicyType.PerRelyingParty -> {
                            val batchSize =
                                env.getRequiredPropertyOrEnvVariable<Int>("$prefix.reusePolicy.options[$index].batchSize")
                            val reissueTriggerUnused =
                                env.getRequiredPropertyOrEnvVariable<Int>(
                                    "$prefix.reusePolicy.options[$index].reissueTriggerUnused",
                                )
                            val reissueTriggerLifetimeLeft =
                                env
                                    .getRequiredPropertyOrEnvVariable<Long>(
                                        "$prefix.reusePolicy.options[$index].reissueTriggerLifetimeLeft",
                                    ).seconds
                            EudiReusePolicy.PerRelyingParty(
                                batchSize,
                                reissueTriggerLifetimeLeft,
                                reissueTriggerUnused,
                            )
                        }
                    }
                }
                index++
            }
            if (options.isEmpty())
                CredentialReusePolicy.None
            else
                CredentialReusePolicy.EUDI(
                    id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
                    options = options,
                )
        }

        else -> {
            CredentialReusePolicy.None
        }
    }
}

internal fun Environment.credentialRequestEncryption(issuerKeystore: () -> KeyStore): CredentialRequestEncryption {
    val isSupported = getProperty<Boolean>("issuer.credentialRequestEncryption.supported") ?: false
    return if (!isSupported) {
        CredentialRequestEncryption.NotSupported
    } else {
        val key =
            when (getProperty<KeyOption>("issuer.credentialRequestEncryption.jwks")) {
                null, KeyOption.GenerateRandom -> {
                    extensionLogger.info("Generating random encryption key for Credential Request Encryption")
                    ECKeyGenerator(Curve.P_256)
                        .keyID(UUID.randomUUID().toString())
                        .keyUse(KeyUse.ENCRYPTION)
                        .algorithm(JWEAlgorithm.ECDH_ES)
                        .generate()
                }

                KeyOption.LoadFromKeystore -> {
                    extensionLogger.info("Loading encryption key for Credential Request Encryption from keystore")
                    val keyAlgorithm =
                        getProperty<String>("issuer.credentialRequestEncryption.jwks.algorithm")?.let {
                            JWEAlgorithm.parse(it)
                        }
                            ?: error("Missing or invalid 'issuer.credentialRequestEncryption.jwks.algorithm' property")

                    when (
                        val loadedJwk =
                            issuerKeystore().loadJwk(this, "issuer.credentialRequestEncryption.jwks")
                    ) {
                        is ECKey -> {
                            require(keyAlgorithm in loadedJwk.supportedJWEAlgorithms) {
                                "${keyAlgorithm.name} cannot be used with an ECKey"
                            }
                            ECKey.Builder(loadedJwk).algorithm(keyAlgorithm).build()
                        }

                        is RSAKey -> {
                            require(keyAlgorithm in loadedJwk.supportedJWEAlgorithms) {
                                "${keyAlgorithm.name} cannot be used with an RSAKey"
                            }
                            RSAKey.Builder(loadedJwk).algorithm(keyAlgorithm).build()
                        }

                        else -> {
                            error("unsupported key type '${loadedJwk.javaClass}'")
                        }
                    }
                }
            }

        val encryptionMethods =
            readNonEmptySet(
                "issuer.credentialRequestEncryption.encryptionMethods",
                EncryptionMethod::parse,
            )
        require(key.supportedEncryptionMethods.containsAll(encryptionMethods)) {
            "Encryption methods: ${encryptionMethods.joinToString { it.name }} cannot be used with the configured encryption key"
        }

        val parameters =
            CredentialRequestEncryptionSupportedParameters(
                encryptionKeys = JWKSet(key),
                methodsSupported = encryptionMethods,
                zipAlgorithmsSupported =
                    readNullableNonEmptySet(
                        "issuer.credentialRequestEncryption.zipAlgorithmsSupported",
                    ) { algorithm -> algorithm.takeIf { it.isNotBlank() }?.let { CompressionAlgorithm(it) } },
            )
        val isRequired = getProperty<Boolean>("issuer.credentialRequestEncryption.required") ?: false
        if (!isRequired) {
            CredentialRequestEncryption.Optional(parameters)
        } else {
            CredentialRequestEncryption.Required(parameters)
        }
    }
}

internal fun Environment.credentialResponseEncryption(): CredentialResponseEncryption {
    val isSupported = getProperty<Boolean>("issuer.credentialResponseEncryption.supported") ?: false
    return if (!isSupported) {
        CredentialResponseEncryption.NotSupported
    } else {
        val parameters =
            CredentialResponseEncryptionSupportedParameters(
                algorithmsSupported =
                    readNonEmptySet(
                        "issuer.credentialResponseEncryption.algorithmsSupported",
                        JWEAlgorithm::parse,
                    ),
                methodsSupported =
                    readNonEmptySet(
                        "issuer.credentialResponseEncryption.encryptionMethods",
                        EncryptionMethod::parse,
                    ),
                zipAlgorithmsSupported =
                    readNullableNonEmptySet(
                        "issuer.credentialResponseEncryption.zipAlgorithmsSupported",
                    ) { algorithm -> algorithm.takeIf { it.isNotBlank() }?.let { CompressionAlgorithm(it) } },
            )
        val isRequired = getProperty<Boolean>("issuer.credentialResponseEncryption.required") ?: false
        if (!isRequired) {
            CredentialResponseEncryption.Optional(parameters)
        } else {
            CredentialResponseEncryption.Required(parameters)
        }
    }
}

internal fun Environment.readRequiredUrl(
    key: String,
    removeTrailingSlash: Boolean = false,
): HttpsUrl =
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

internal fun <T> Environment.readNonEmptySet(
    key: String,
    f: (String) -> T?,
): NonEmptySet<T> {
    val nonEmptySet =
        getRequiredProperty<MutableSet<String>>(key)
            .mapNotNull(f)
            .toNonEmptySetOrNull()
    return checkNotNull(nonEmptySet) { "Missing or incorrect values values for key `$key`" }
}

internal fun Environment.getBoolean(s: String): Boolean? = getProperty(s)?.toBooleanStrictOrNull()

internal fun Environment.getBoolean(
    s: String,
    default: Boolean,
): Boolean = getProperty(s)?.toBooleanStrictOrNull() ?: default

internal fun <T> Environment.readNullableNonEmptySet(
    key: String,
    f: (String) -> T?,
): NonEmptySet<T>? =
    getProperty<MutableSet<String>>(key)
        ?.mapNotNull(f)
        ?.toNonEmptySetOrNull()

internal fun Environment.duration(key: String): Duration? = getProperty(key)?.let { Duration.parse(it) }?.takeIf { it.isPositive() }

internal fun HttpsUrl.appendPath(path: String): HttpsUrl =
    HttpsUrl.unsafe(
        UriComponentsBuilder
            .fromUriString(externalForm)
            .path(path)
            .build()
            .toUriString(),
    )

/**
 * Loads a key pair alongside its associated certificate chain as a JWK.
 *
 * This method expects to find the following properties in the provided [environment].
 * - [prefix].alias -> alias of the key pair to load
 * - [prefix].password -> password of the key pair
 *
 * @receiver the [KeyStore] from which to load the [JWK]
 */
@Suppress("SameParameterValue")
internal fun KeyStore.loadJwk(
    environment: Environment,
    prefix: String,
): JWK {
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

    val keyAlias = environment.getRequiredProperty(property("alias"))
    val keyPassword = environment.getProperty(property("password"))?.takeIf { it.isNotBlank() }

    val jwk = JWK.load(this, keyAlias, keyPassword?.toCharArray())
    val chain =
        getCertificateChain(keyAlias)
            .orEmpty()
            .map { certificate -> certificate as X509Certificate }
            .toList()

    return when {
        chain.isNotEmpty() -> jwk.withCertificateChain(chain)
        else -> jwk
    }
}

internal fun Environment.getPropertyOrEnvVariable(property: String): String? =
    getProperty(property) ?: getProperty(toEnvironmentVariable(property))

internal inline fun <reified T : Any> Environment.getRequiredPropertyOrEnvVariable(property: String): T =
    getProperty<T>(property) ?: getProperty<T>(toEnvironmentVariable(property))
        ?: throw IllegalStateException("Property $property or environment variable ${toEnvironmentVariable(property)} not found")

internal fun toEnvironmentVariable(property: String): String =
    property
        .replace(".", "_")
        .replace("[", "_")
        .replace("]", "")
        .replace("-", "")
        .uppercase()

internal object IssuerFactory {
    data class Ctx(
        val clock: Clock,
        val timeZone: TimeZone,
        val env: Environment,
        val credentialIssuerId: CredentialIssuerId,
        val validateProof: ValidateProof,
        val storeIssuedCredential: StoreIssuedCredential,
        val allocateStatus: AllocateStatus,
        val generateNotificationId: GenerateNotificationId,
    )

    context(ctx: Ctx)
    fun mdl(issuerSigningKey: IssuerSigningKey): IssueMdoc<MobileDrivingLicence> {
        val validity = ctx.env.duration("issuer.mdl.mso_mdoc.encoder.duration") ?: 31.days
        val jwtProofsSupportedSigningAlgorithms =
            ctx.env.readNonEmptySet(
                "issuer.mdl.jwtProofs.supportedSigningAlgorithms",
                JWSAlgorithm::parse,
            )
        val deviceBinding =
            DeviceBinding.ts3(
                jwtProofsSupportedSigningAlgorithms,
                PreferredKeyStorageStatusPeriod(validity),
            )
        val mdlIssuerReusePolicy = credentialReusePolicy(ctx.env, "issuer.mdl")
        val generateNotificationId =
            ctx.generateNotificationId.takeIf {
                ctx.env.getProperty<Boolean>("issuer.mdl.notifications.enabled") ?: true
            }
        return IssueMobileDrivingLicence(
            clock = ctx.clock,
            getAttestationAttributes = RandomMobileDrivingLicence(),
            issuerSigningKey = issuerSigningKey,
            deviceBinding = deviceBinding,
            credentialReusePolicy = mdlIssuerReusePolicy,
            validity = validity,
            validateProof = ctx.validateProof,
            generateNotificationId = generateNotificationId,
            storeIssuedCredential = ctx.storeIssuedCredential,
            allocateStatus = ctx.allocateStatus,
        )
    }

    context(ctx: Ctx)
    fun pidInMdoc(
        issuerSigningKey: IssuerSigningKey,
        getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
    ): IssueMdoc<PidAttributes> {
        val duration = ctx.env.duration("issuer.pid.mso_mdoc.encoder.duration") ?: 31.days
        val jwtProofsSupportedSigningAlgorithms =
            ctx.env.readNonEmptySet(
                "issuer.pid.mso_mdoc.jwtProofs.supportedSigningAlgorithms",
                JWSAlgorithm::parse,
            )
        val pidMsoMdocReusePolicy = credentialReusePolicy(ctx.env, "issuer.pid.mso_mdoc")

        return IssueMsoMdocPid(
            clock = ctx.clock,
            getAttestationAttributes = getAttestationAttributes,
            issuerSigningKey = issuerSigningKey,
            deviceBinding =
                DeviceBinding.ts3(
                    jwtProofsSupportedSigningAlgorithms,
                    PreferredKeyStorageStatusPeriod(duration),
                ),
            credentialReusePolicy = pidMsoMdocReusePolicy,
            validity = duration,
            validateProof = ctx.validateProof,
            generateNotificationId =
                ctx.generateNotificationId.takeIf {
                    ctx.env.getProperty<Boolean>("issuer.pid.mso_mdoc.notifications.enabled") ?: true
                },
            storeIssuedCredential = ctx.storeIssuedCredential,
            allocateStatus = ctx.allocateStatus,
        )
    }

    context(ctx: Ctx)
    fun pidInSdJwtVc(
        issuerSigningKey: IssuerSigningKey,
        getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
    ): IssueSdJwtVcPid {
        val expiresIn = ctx.env.duration("issuer.pid.sd_jwt_vc.duration") ?: 31.days
        val notUseBefore = ctx.env.duration("issuer.pid.sd_jwt_vc.notUseBefore")
        val pidSdJwtVcReusePolicy = credentialReusePolicy(ctx.env, "issuer.pid.sd_jwt_vc")

        val digestsHashAlgorithm =
            ctx.env.getProperty<HashAlgorithm>("issuer.pid.sd_jwt_vc.digests.hashAlgorithm") ?: HashAlgorithm.SHA_256
        val jwtProofsSupportedSigningAlgorithms =
            ctx.env.readNonEmptySet("issuer.pid.sd_jwt_vc.jwtProofs.supportedSigningAlgorithms", JWSAlgorithm::parse)

        return IssueSdJwtVcPid(
            clock = ctx.clock,
            getAttestationAttributes = getAttestationAttributes,
            issuerSigningKey = issuerSigningKey,
            credentialIssuerId = ctx.credentialIssuerId,
            digestsHashAlgorithm = digestsHashAlgorithm,
            deviceBinding =
                DeviceBinding.ts3(
                    jwtProofsSupportedSigningAlgorithms,
                    PreferredKeyStorageStatusPeriod(expiresIn),
                ),
            credentialReusePolicy = pidSdJwtVcReusePolicy,
            validity = expiresIn,
            validateProof = ctx.validateProof,
            generateNotificationId =
                ctx.generateNotificationId.takeIf {
                    ctx.env.getBoolean("issuer.pid.sd_jwt_vc.notifications.enabled") ?: true
                },
            storeIssuedCredential = ctx.storeIssuedCredential,
            allocateStatus = ctx.allocateStatus,
            calculateNotUseBefore = notUseBefore?.let { duration -> { iat -> iat + duration } },
        )
    }

    context(ctx: Ctx)
    fun learningCredentialInSdJwtVc(
        issuerSigningKey: IssuerSigningKey,
        getPidData: GetAttestationAttributes<PidAttributes>,
    ): IssueLearningCredential {
        val jwtProofsSupportedSigningAlgorithms =
            ctx.env.readNonEmptySet(
                "issuer.learningCredential.jwtProofs.supportedSigningAlgorithms",
                JWSAlgorithm::parse,
            )
        val learningCredentialReusePolicy =
            credentialReusePolicy(ctx.env, "issuer.learningCredential")
        val validity = Duration.parse(ctx.env.getProperty("issuer.learningCredential.validity", "P31D"))
        val digestHashAlgorithm =
            ctx.env.getProperty<HashAlgorithm>(
                "issuer.learningCredential.sdJwtVc.encoder.digests.hashAlgorithm",
            ) ?: HashAlgorithm.SHA_256

        val notificationsEnabled =
            ctx.env.getProperty<Boolean>("issuer.learningCredential.notifications.enabled") ?: true

        return IssueLearningCredential(
            sdJwtVcSerialization = SdJwtVcSerialization.Compact,
            clock = ctx.clock,
            getAttestationAttributes =
                IssueLearningCredential.randomLearningCredentials(
                    ctx.clock,
                    getPidData,
                ),
            issuerSigningKey = issuerSigningKey,
            digestsHashAlgorithm = digestHashAlgorithm,
            deviceBinding =
                DeviceBinding.Required(
                    jwtProofsSupportedSigningAlgorithms,
                    KeyAttestationRequirement.ts3(
                        PreferredKeyStorageStatusPeriod(validity),
                    ),
                ),
            credentialReusePolicy = learningCredentialReusePolicy,
            validity = validity,
            validateProof = ctx.validateProof,
            generateNotificationId = ctx.generateNotificationId.takeIf { notificationsEnabled },
            storeIssuedCredential = ctx.storeIssuedCredential,
        )
    }
}

internal fun getPidDataFromKeyCloak(
    clock: Clock,
    timeZone: TimeZone,
    env: Environment,
    webClient: WebClient,
): GetAttestationAttributes<PidAttributes> {
    val keycloakProperties =
        KeycloakConfigurationProperties(
            env.getRequiredProperty<URL>("issuer.keycloak.server-url"),
            env.getRequiredProperty("issuer.keycloak.authentication-realm"),
            env.getRequiredProperty("issuer.keycloak.client-id"),
            env.getRequiredProperty("issuer.keycloak.username"),
            env.getRequiredProperty("issuer.keycloak.password"),
            env.getRequiredProperty("issuer.keycloak.user-realm"),
        )
    return GetPidDataFromKeyCloak(
        issuerCountry = env.getRequiredProperty("issuer.pid.issuingCountry").let(::IsoCountry),
        issuingJurisdiction = env.getProperty("issuer.pid.issuingJurisdiction"),
        clock = clock,
        timeZone = timeZone,
        webClient = webClient,
        keyCloak = Url(keycloakProperties.serverUrl.toExternalForm()),
        administrationClient =
            AdministrationClient(
                realm = Realm(keycloakProperties.authenticationRealm),
                client = Credentials(username = keycloakProperties.clientId, password = null),
                admin =
                    Credentials(
                        username = keycloakProperties.username,
                        password = keycloakProperties.password,
                    ),
            ),
        users = Realm(keycloakProperties.userRealm),
    )
}

internal fun validateProof(
    credentialIssuerId: CredentialIssuerId,
    isTrustedKeyAttestationIssuer: IsTrustedKeyAttestationIssuer,
    verifyNonce: VerifyNonce,
): ValidateProof {
    val verifyKeyAttestation = VerifyKeyAttestation(isTrustedKeyAttestationIssuer = isTrustedKeyAttestationIssuer)
    val validateJwtProofWithKeyAttestation =
        ValidateJwtProofWithKeyAttestation(credentialIssuerId, verifyKeyAttestation)
    val validateAttestationProof = ValidateAttestationProof(verifyKeyAttestation)
    return ValidateProof(
        validateJwtProofWithKeyAttestation,
        validateAttestationProof,
        verifyNonce,
    )
}

internal fun httpProxy(env: Environment): HttpProxy? =
    env.getProperty("issuer.http.proxy.url")?.let {
        val url = Url(it)
        val username = env.getProperty("issuer.http.proxy.username")
        val password = env.getProperty("issuer.http.proxy.password")
        HttpProxy(url, username, password)
    }
