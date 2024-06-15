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

import com.authlete.cose.constants.COSEAlgorithms
import com.authlete.cose.constants.COSEEllipticCurves
import com.nimbusds.jose.jwk.JWK
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
    val holderPublicKey: JWK,
    val issuedAt: Instant,
    val notificationId: NotificationId? = null,
)

/**
 * The unique identifier of a Credential.
 */
@JvmInline
value class CredentialIdentifier(val value: String)

@JvmInline
value class CoseAlgorithm private constructor(val value: Int) {

    fun name(): String =
        checkNotNull(COSEAlgorithms.getNameByValue(value)) { "Cannot find name for COSE algorithm $value" }

    companion object {

        val ES256 = CoseAlgorithm(COSEAlgorithms.ES256)
        val ES384 = CoseAlgorithm(COSEAlgorithms.ES384)
        val ES512 = CoseAlgorithm(COSEAlgorithms.ES512)

        operator fun invoke(value: Int): Result<CoseAlgorithm> = runCatching {
            require(COSEAlgorithms.getNameByValue(value) != null) { "Unsupported COSE algorithm $value" }
            CoseAlgorithm(value)
        }

        operator fun invoke(name: String): Result<CoseAlgorithm> = runCatching {
            val value = COSEAlgorithms.getValueByName(name)
            require(value != 0) { "Unsupported COSE algorithm $name" }
            CoseAlgorithm(value)
        }
    }
}

@JvmInline
value class CoseCurve private constructor(val value: Int) {

    fun name(): String =
        checkNotNull(COSEEllipticCurves.getNameByValue(value)) { "Cannot find name for COSE Curve $value" }

    companion object {

        val P_256 = CoseCurve(COSEEllipticCurves.P_256)
        val P_384 = CoseCurve(COSEEllipticCurves.P_384)
        val P_521 = CoseCurve(COSEEllipticCurves.P_521)

        operator fun invoke(value: Int): Result<CoseCurve> = runCatching {
            require(COSEEllipticCurves.getNameByValue(value) != null) { "Unsupported COSE Curve $value" }
            CoseCurve(value)
        }

        operator fun invoke(name: String): Result<CoseCurve> = runCatching {
            val value = COSEEllipticCurves.getValueByName(name)
            require(value != 0) { "Unsupported COSE Curve $name" }
            CoseCurve(value)
        }
    }
}
