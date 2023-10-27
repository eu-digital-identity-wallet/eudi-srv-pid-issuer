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

import arrow.core.NonEmptySet
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm
import java.net.MalformedURLException
import java.net.URL
import java.util.*

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
                println("Warning: using unsafe URL $url")
                HttpsUrl(this)
            }
    }
}

@JvmInline
value class Scope(val value: String)

@JvmInline
value class Format(val value: String)

typealias CredentialIssuerId = HttpsUrl

data class ImageUrl(val url: HttpsUrl, val alternativeText: String? = null)
data class DisplayName(val name: String, val locale: Locale)
typealias Color = String

data class CredentialDisplay(
    val name: DisplayName,
    val logo: ImageUrl? = null,
    val description: String? = null,
    val backgroundColor: Color? = null,
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
    data class Jwk(val cryptographicSuitesSupported: NonEmptySet<JWSAlgorithm>) : CryptographicBindingMethod

    /**
     * Support for keys expressed as a COSE Key object
     */
    data class CoseKey(val cryptographicSuitesSupported: NonEmptySet<JWSAlgorithm>) : CryptographicBindingMethod
    data class Mso(val cryptographicSuitesSupported: NonEmptySet<JWSAlgorithm>) : CryptographicBindingMethod
    data class DidMethod(
        val didMethod: String,
        val cryptographicSuitesSupported: NonEmptySet<JWSAlgorithm>,
    ) : CryptographicBindingMethod

    data class DidAnyMethod(val cryptographicSuitesSupported: NonEmptySet<JWSAlgorithm>) : CryptographicBindingMethod
}

fun CryptographicBindingMethod.methodName(): String = when (this) {
    is CryptographicBindingMethod.Jwk -> "jwk"
    is CryptographicBindingMethod.CoseKey -> "cose_key"
    is CryptographicBindingMethod.Mso -> "mso"
    is CryptographicBindingMethod.DidMethod -> "did:$didMethod"
    is CryptographicBindingMethod.DidAnyMethod -> "DID"
}

/**
 * Representing metadata about a separate credential type
 * that the Credential Issuer can issue
 */
sealed interface CredentialMetaData {
    val format: Format
    val scope: Scope?
    val display: List<CredentialDisplay>
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
}

fun CredentialMetaData.cryptographicSuitesSupported(): NonEmptySet<JWSAlgorithm> =
    cryptographicBindingMethodsSupported.map { method ->
        when (method) {
            is CryptographicBindingMethod.CoseKey -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.DidAnyMethod -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.DidMethod -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.Jwk -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.Mso -> method.cryptographicSuitesSupported
        }
    }.flatten().toNonEmptySetOrNull()!!
