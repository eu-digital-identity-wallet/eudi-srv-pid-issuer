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

import arrow.core.*
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.util.Base64
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.pidissuer.domain.*
import kotlinx.coroutines.reactor.awaitSingle
import org.slf4j.LoggerFactory
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.env.getRequiredProperty
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

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

internal suspend fun WebClient.authorizationServerSupportedDPoPJWSAlgorithms(authorizationServerMetadata: URI): NonEmptySet<JWSAlgorithm>? =
    Either
        .catch {
            val metadata =
                get()
                    .uri(authorizationServerMetadata)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono<String>()
                    .timeout(5.seconds.toJavaDuration())
                    .awaitSingle()
            OIDCProviderMetadata.parse(metadata).dPoPJWSAlgs?.toNonEmptySetOrNull()
        }.getOrElse {
            extensionLogger.warn("Unable to fetch Authorization Server metadata. DPoP support will be disabled.", it)
            null
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
