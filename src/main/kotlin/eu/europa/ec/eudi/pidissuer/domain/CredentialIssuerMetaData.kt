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
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec.ZIP_ALGORITHMS
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import java.util.*

/**
 * Encryption algorithms and methods supported for encrypting Credential Responses.
 *
 * @param encryptionKeys a Json Web Key Set (JWK Set) RFC7517 containing the one or more
 * public keys to be used by the Wallet as an input to a key agreement
 * for encryption of the Credential Request
 * @param methodsSupported a list of the JWE RFC7516 encryption algorithms
 * (enc values) RFC7518 supported by the Credential
 * and/or Batch Credential Endpoint to decode the Credential or
 * Batch Credential Response in a JWT RFC7519
 * @param zipAlgorithmsSupported a list of the JWE RFC7516 compression
 * algorithms (zip values) RFC7518 supported by the Credential Endpoint
 * to uncompress the Credential Request after decryption
 */
data class CredentialRequestEncryptionSupportedParameters(
    val encryptionKeys: JWKSet,
    val methodsSupported: NonEmptySet<EncryptionMethod>,
    val zipAlgorithmsSupported: NonEmptySet<CompressionAlgorithm>?,
) {
    init {
        require(encryptionKeys.keys.isNotEmpty()) { "encryptionKeys must contain at least one key" }
        require(encryptionKeys.keys.all { it.isPrivate }) { "encryptionKeys must contain only private keys" }
        require(encryptionKeys.keys.all { !it.keyID.isNullOrBlank() }) { "encryptionKeys must contain keys with a kid value" }
        require(encryptionKeys.keys.all { it.algorithm != null }) { "encryptionKeys must contain keys with an alg value" }
        require(encryptionKeys.keys.all { it.algorithm is JWEAlgorithm }) { "encryptionKeys must contain keys with a JWE alg value" }
        require(
            encryptionKeys.keys.all {
                when (it) {
                    is ECKey -> JWEAlgorithm.Family.ECDH_ES.contains(it.algorithm)
                    is RSAKey -> JWEAlgorithm.Family.RSA.contains(it.algorithm)
                    else -> false
                }
            },
        ) {
            "encryptionKeys must contain only EC or RSA keys with a compatible JWE alg value"
        }
        require(zipAlgorithmsSupported?.all { it.name in ZIP_ALGORITHMS } ?: true) {
            "zipAlgorithmsSupported must be one of ${ZIP_ALGORITHMS.joinToString(", ") { it }}"
        }
    }
}

/**
 * Encryption algorithms and methods supported for encrypting Credential Responses.
 *
 * @param algorithmsSupported  a list of the JWE RFC7516 encryption
 * algorithms (alg values) RFC7518 supported by the Credential and/or
 * Batch Credential Endpoint to encode the Credential or
 * Batch Credential Response in a JWT RFC7519
 * @param methodsSupported a list of the JWE RFC7516 encryption algorithms
 * (enc values) RFC7518 supported by the Credential
 * and/or Batch Credential Endpoint to encode the Credential or
 * Batch Credential Response in a JWT RFC7519
 * @param zipAlgorithmsSupported a list of the JWE RFC7516 compression
 * algorithms (zip values) RFC7518 supported by the Credential Endpoint
 * to compress the Credential Response before encryption
 */
data class CredentialResponseEncryptionSupportedParameters(
    val algorithmsSupported: NonEmptySet<JWEAlgorithm>,
    val methodsSupported: NonEmptySet<EncryptionMethod>,
    val zipAlgorithmsSupported: NonEmptySet<CompressionAlgorithm>?,
) {
    init {
        require(zipAlgorithmsSupported?.all { it.name in ZIP_ALGORITHMS } ?: true) {
            "zipAlgorithmsSupported must be one of ${ZIP_ALGORITHMS.joinToString(", ") { it }}"
        }
    }
}

sealed interface CredentialResponseEncryption {

    /**
     * The Credential Issuer indicates that additional
     * Credential Response encryption is not supported
     */
    data object NotSupported : CredentialResponseEncryption

    /**
     * The Credential Issuer supports but does not require additional encryption
     * on top of TLS for the Credential Response and can accept encryption parameters
     * in the Credential Request and/or Batch Credential Request.
     *
     * @param parameters the supported encryption algorithms and methods
     */
    data class Optional(
        val parameters: CredentialResponseEncryptionSupportedParameters,
    ) : CredentialResponseEncryption

    /**
     * The Credential Issuer requires additional encryption
     * on top of TLS for the Credential Response and expects encryption parameters
     * in the Credential Request and/or Batch Credential Request.
     *
     * @param parameters the supported encryption algorithms and methods
     */
    data class Required(
        val parameters: CredentialResponseEncryptionSupportedParameters,
    ) : CredentialResponseEncryption
}

sealed interface CredentialRequestEncryption {

    /**
     * The Credential Issuer indicates that additional
     * Credential Request encryption is not supported
     */
    data object NotSupported : CredentialRequestEncryption

    /**
     * The Credential Issuer supports but does not require additional encryption
     * on top of TLS for the Credential Request and can accept encryption parameters
     * in the Credential Request and/or Batch Credential Request.
     *
     * @param parameters the supported encryption algorithms and methods
     */
    data class Optional(
        val parameters: CredentialRequestEncryptionSupportedParameters,
    ) : CredentialRequestEncryption

    /**
     * The Credential Issuer requires additional encryption
     * on top of TLS for the Credential Request and expects encryption parameters
     * in the Credential Request and/or Batch Credential Request.
     *
     * @param parameters the supported encryption algorithms and methods
     */
    data class Required(
        val parameters: CredentialRequestEncryptionSupportedParameters,
    ) : CredentialRequestEncryption
}

fun <T> CredentialRequestEncryption.fold(
    ifNotSupported: T,
    ifOptional: (CredentialRequestEncryption.Optional) -> T,
    ifRequired: (CredentialRequestEncryption.Required) -> T,
): T = when (this) {
    CredentialRequestEncryption.NotSupported -> ifNotSupported
    is CredentialRequestEncryption.Optional -> ifOptional(this)
    is CredentialRequestEncryption.Required -> ifRequired(this)
}

fun <T> CredentialResponseEncryption.fold(
    ifNotSupported: T,
    ifOptional: (CredentialResponseEncryption.Optional) -> T,
    ifRequired: (CredentialResponseEncryption.Required) -> T,
): T = when (this) {
    CredentialResponseEncryption.NotSupported -> ifNotSupported
    is CredentialResponseEncryption.Optional -> ifOptional(this)
    is CredentialResponseEncryption.Required -> ifRequired(this)
}

data class CredentialIssuerDisplay(
    val name: String? = null,
    val locale: Locale? = null,
    val logo: ImageUri? = null,
) {
    init {
        require(name != null || logo != null) {
            "provide at least one of 'name' or 'logo'"
        }
    }
}

/**
 * @param id The Credential Issuer's identifier
 * @param authorizationServers Identifiers of the OAuth 2.0 Authorization
 * Servers (as defined in RFC8414) the Credential Issuer relies on for authorization
 * @param credentialEndPoint URL of the Credential Issuer's Credential Endpoint.
 * This URL MUST use the https scheme and MAY contain port, path,
 * and query parameter components
 * @param batchCredentialIssuance whether the credential endpoint supports batch issuance or not
 * @param deferredCredentialEndpoint  URL of the Credential Issuer's
 * Deferred Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path,
 * and query parameter components.
 * If omitted, the Credential Issuer does not support the Deferred Credential Endpoint
 * @param notificationEndpoint URL of the Credential Issuer's Notification Endpoint. This URL MUST use
 * the https scheme and MAY contain port, path, and query parameter components. If omitted, the
 * Credential Issuer does not support the Notification Endpoint.
 * @param nonceEndpoint URL of the Credential Issuer's Nonce Endpoint. If omitted,
 * the Credential Issuer does not support the Nonce Endpoint.
 * @param credentialRequestEncryption indicates whether the issuer requires the
 * Credential Request encrypted or not.
 * @param credentialResponseEncryption indicates whether the issuer requires the
 * Credential Response encrypted or not.
 * @param display display properties of a Credential Issuer for a certain language
 * @param specificCredentialIssuers the list of the specific issuers supported
 */
data class CredentialIssuerMetaData(
    val id: CredentialIssuerId,
    val authorizationServers: List<HttpsUrl>,
    val credentialEndPoint: HttpsUrl,
    val batchCredentialIssuance: BatchCredentialIssuance,
    val deferredCredentialEndpoint: HttpsUrl? = null,
    val notificationEndpoint: HttpsUrl? = null,
    val nonceEndpoint: HttpsUrl? = null,
    val credentialRequestEncryption: CredentialRequestEncryption,
    val credentialResponseEncryption: CredentialResponseEncryption,
    val display: List<CredentialIssuerDisplay> = emptyList(),
    val specificCredentialIssuers: List<IssueSpecificCredential>,
) {
    init {
        val displayLocales = display.map { it.locale }
        require(displayLocales.size == displayLocales.distinct().size) {
            "only one display object can be configured per locale"
        }

        val credentialConfigurationIds = specificCredentialIssuers.map { it.supportedCredential.id }
        require(credentialConfigurationIds.size == credentialConfigurationIds.distinct().size) {
            "credential configuration ids must be unique"
        }
    }

    val credentialConfigurationsSupported: List<CredentialConfiguration>
        get() = specificCredentialIssuers.map { it.supportedCredential }
}

/**
 * Indicates whether the Credential Endpoint can support batch issuance or not.
 */
sealed interface BatchCredentialIssuance {

    /**
     * Batch credential issuance is not supported.
     */
    data object NotSupported : BatchCredentialIssuance

    /**
     * Batch credential issuance is supported.
     */
    data class Supported(val batchSize: Int) : BatchCredentialIssuance {
        init {
            require(batchSize > 0) { "Batch size must be greater than 0" }
        }
    }
}
