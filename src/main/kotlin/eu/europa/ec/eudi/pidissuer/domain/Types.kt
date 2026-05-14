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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import org.slf4j.LoggerFactory
import java.net.MalformedURLException
import java.net.URI
import java.net.URL
import java.util.*
import kotlin.time.Instant

private val logHttpsUrl = LoggerFactory.getLogger(HttpsUrl::class.java)

@JvmInline
value class HttpsUrl private constructor(val value: URL) {
    val externalForm: String
        get() = value.toExternalForm()!!

    companion object {
        fun of(url: URL): HttpsUrl? = url.takeIf { it.protocol == "https" }?.run { HttpsUrl(this) }
        fun of(url: String): HttpsUrl? =
            try {
                of(URL(url))
            } catch (_: MalformedURLException) {
                null
            }

        fun unsafe(url: String): HttpsUrl =
            URL(url).run {
                logHttpsUrl.warn("Using unsafe URL $url")
                HttpsUrl(this)
            }
    }
}

@JvmInline
value class Scope(val value: String)

@JvmInline
value class Format(val value: String)

typealias CredentialIssuerId = HttpsUrl

data class ImageUri(val uri: URI, val alternativeText: String? = null)

@JvmInline
value class BackgroundImage(val uri: URI)

data class DisplayName(val name: String, val locale: Locale)
typealias Color = String

data class CredentialDisplay(
    val name: DisplayName,
    val logo: ImageUri? = null,
    val description: String? = null,
    val backgroundColor: Color? = null,
    val backgroundImage: BackgroundImage? = null,
    val textColor: Color? = null,
)

typealias Display = Map<Locale, String>

data class ClaimDefinition(
    val path: ClaimPath,
    val mandatory: Boolean? = null,
    val display: Display = emptyMap(),
    val nested: List<ClaimDefinition> = emptyList(),
) {
    init {
        require(path.last() is ClaimPathElement.Claim) { "The provided ClaimPath does not correspond to an Attribute" }
        require(nested.all { path == it.path.parent() }) {
            "'nested' contains Claims with ClaimPaths that are not nested under this Claim"
        }
    }

    val name: String
        get() = (path.last() as ClaimPathElement.Claim).name

    companion object
}

/**
 * Identify how the Credential is bound to the identifier
 * of the End-User who possesses the Credential
 */
sealed interface CryptographicBindingMethod {

    /**
     * Support for keys in JWK format RFC7517
     */
    data object Jwk : CryptographicBindingMethod

    /**
     * Support for keys expressed as a COSE Key object
     */
    data object CoseKey : CryptographicBindingMethod

    /**
     * Support for a specific DID method
     */
    data class DidMethod(val didMethod: String) : CryptographicBindingMethod

    /**
     * Support for any DID method
     */
    data object DidAnyMethod : CryptographicBindingMethod
}

/**
 * Credential that have issued by a specific issuing service.
 */
data class IssuedCredentials(
    val format: Format,
    val type: String,
    val holder: String,
    val holderPublicKeys: NonEmptyList<JWK>,
    val issuedAt: Instant,
    val notificationId: NotificationId? = null,
)

/**
 * The unique identifier of a Credential.
 */
@JvmInline
value class CredentialIdentifier(val value: String)

/**
 * A Status List Token per Token Status List.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/</a>
 */
@Serializable
data class StatusListToken(
    @Required @SerialName(TokenStatusListSpec.URI)
    @Serializable(with = UriStringSerializer::class)
    val statusList: URI,
    @Required @SerialName(TokenStatusListSpec.IDX)
    val index: UInt,
)

enum class IntegrityHashAlgorithm(val id: String) {
    SHA_256("sha256"),
    SHA_384("sha384"),
    SHA_512("sha512"),
}

@JvmInline
value class CoseAlgorithm(val value: Int)

@JvmInline
@Serializable
value class NonBlankString(val value: String) {
    init {
        require(value.isNotBlank())
    }

    override fun toString(): String = value
}

object UriStringSerializer : KSerializer<URI> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("UriStringSerializer", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: URI,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): URI = URI.create(decoder.decodeString())
}

object UrlStringSerializer : KSerializer<URL> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("UrlStringSerializer", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: URL,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): URL = URI.create(decoder.decodeString()).toURL()
}

object InstantLongSerializer : KSerializer<Instant> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("InstantLongSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Instant {
        return Instant.fromEpochSeconds(decoder.decodeLong())
    }

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeLong(value.epochSeconds)
    }
}

object JWKNonEmptyListSerializer : KSerializer<NonEmptyList<JWK>> by NonEmptyListSerializer(JWKJsonObjectSerializer)

object JWKJsonObjectSerializer : KSerializer<JWK> {
    private val serializer = JsonObject.serializer()

    override val descriptor: SerialDescriptor = SerialDescriptor("JWKJsonObjectSerializer", serializer.descriptor)

    override fun serialize(encoder: Encoder, value: JWK) {
        val serialized = jsonSupport.decodeFromString<JsonObject>(value.toJSONString())
        encoder.encodeSerializableValue(serializer, serialized)
    }

    override fun deserialize(decoder: Decoder): JWK {
        val serialized = decoder.decodeSerializableValue(serializer)
        return JWK.parse(jsonSupport.encodeToString(serialized))
    }
}
