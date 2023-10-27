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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import kotlinx.serialization.json.JsonElement

sealed interface CredentialResponseEncryption {

    /**
     * The Credential Issuer indicates that no additional
     * Credential Response encryption is required
     */
    data object NotRequired : CredentialResponseEncryption

    /**
     * The Credential Issuer requires additional encryption on top of TLS
     * for the Credential Response and expects encryption parameters to
     * be present in the Credential Request and/or Batch Credential Request
     *
     * @param algorithmsSupported  a list of the JWE RFC7516 encryption
     * algorithms (alg values) RFC7518 supported by the Credential and/or
     * Batch Credential Endpoint to encode the Credential or
     * Batch Credential Response in a JWT RFC7519
     * @param encryptionMethods a list of the JWE RFC7516 encryption algorithms
     * (enc values) RFC7518 supported by the Credential
     * and/or Batch Credential Endpoint to encode the Credential or
     * Batch Credential Response in a JWT RFC7519
     *
     */
    data class Required(
        val algorithmsSupported: List<JWEAlgorithm>,
        val encryptionMethods: List<EncryptionMethod>,
    ) : CredentialResponseEncryption
}

fun <T> CredentialResponseEncryption.fold(
    ifNotRequired: T,
    ifRequired: (CredentialResponseEncryption.Required) -> T,
): T = when (this) {
    CredentialResponseEncryption.NotRequired -> ifNotRequired
    is CredentialResponseEncryption.Required -> ifRequired(this)
}

/**
 * @param id The Credential Issuer's identifier
 * @param authorizationServer Identifier of the OAuth 2.0 Authorization
 * Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization
 * @param credentialEndPoint URL of the Credential Issuer's Credential Endpoint.
 * This URL MUST use the https scheme and MAY contain port, path,
 * and query parameter components
 * @param batchCredentialEndpoint URL of the Credential Issuer's Batch Credential Endpoint.
 * This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
 * If omitted, the Credential Issuer does not support the Batch Credential Endpoint
 * @param deferredCredentialEndpoint  URL of the Credential Issuer's
 * Deferred Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path,
 * and query parameter components.
 * If omitted, the Credential Issuer does not support the Deferred Credential Endpoint
 * @param credentialResponseEncryption indicates whether the issuer requires the
 * Credential Response encrypted or not.
 * @param display display properties of a Credential Issuer for a certain language
 * @param credentialsSupported
 */
data class CredentialIssuerMetaData(
    val id: CredentialIssuerId,
    val authorizationServer: HttpsUrl,
    val credentialEndPoint: HttpsUrl,
    val batchCredentialEndpoint: HttpsUrl? = null,
    val deferredCredentialEndpoint: HttpsUrl? = null,
    val credentialResponseEncryption: CredentialResponseEncryption = CredentialResponseEncryption.NotRequired,
    val display: Display = emptyMap(),
    val specificCredentialIssuers: List<IssueSpecificCredential<JsonElement>>,
) {
    val credentialsSupported: List<CredentialMetaData>
        get() = specificCredentialIssuers.map { it.supportedCredential }
}
