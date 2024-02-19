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
package eu.europa.ec.eudi.pidissuer.domain

import eu.europa.ec.eudi.pidissuer.port.input.ClientId
import org.slf4j.LoggerFactory
import java.net.MalformedURLException
import java.net.URI
import java.net.URL
import java.time.Instant
import java.util.*

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
            } catch (e: MalformedURLException) {
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
data class DisplayName(val name: String, val locale: Locale)
typealias Color = String

data class CredentialDisplay(
    val name: DisplayName,
    val logo: ImageUri? = null,
    val description: String? = null,
    val backgroundColor: Color? = null,
    val backgroundImage: ImageUri? = null,
    val textColor: Color? = null,
)

typealias Display = Map<Locale, String>

data class AttributeDetails(
    val name: String,
    val mandatory: Boolean = false,
    val valueType: String? = null,
    val display: Display = emptyMap(),
)

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
 * A credential that was issued by a specific issuing service.
 */
data class IssuedCredential(
    val format: Format,
    val type: String,
    val holder: String,
    val issuedAt: Instant,
    val clientId: ClientId? = null,
    val notificationId: NotificationId? = null,
)

/**
 * The unique identifier of a Credential.
 */
@JvmInline
value class CredentialIdentifier(val value: String)
