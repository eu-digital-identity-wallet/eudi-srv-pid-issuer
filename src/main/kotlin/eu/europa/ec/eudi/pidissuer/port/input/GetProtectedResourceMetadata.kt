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
package eu.europa.ec.eudi.pidissuer.port.input

import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.domain.RFC9728
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class BearerMethodTO {
    @SerialName(RFC9728.BEARER_METHOD_HEADER)
    HEADER,

    @SerialName(RFC9728.BEARER_METHOD_BODY)
    BODY,

    @SerialName(RFC9728.BEARER_METHOD_QUERY)
    QUERY,
}

@Serializable
data class ProtectedResourceMetadataTO(
    @Required @SerialName(RFC9728.RESOURCE) val resource: String,
    @SerialName(RFC9728.AUTHORIZATION_SERVERS) val authorizationServers: List<String>? = null,
    @SerialName(RFC9728.JWKS_URI) val jwksUri: String? = null,
    @SerialName(RFC9728.SCOPES_SUPPORTED) val scopesSupported: List<String>? = null,
    @SerialName(RFC9728.BEARER_METHODS_SUPPORTED) val bearerMethodsSupported: List<BearerMethodTO>? = null,
    @SerialName(RFC9728.DPOP_SIGNING_ALGORITHMS_SUPPORTED) val dpopSigningAlgorithmsSupported: List<String>? = null,
    @SerialName(RFC9728.DPOP_BOUND_ACCESS_TOKEN_REQUIRED) val dpopBoundAccessTokenRequired: Boolean? = null,

)

class GetProtectedResourceMetadata(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val jwksUri: HttpsUrl,
    private val dPoPConfigurationProperties: DPoPConfigurationProperties,
) {
    fun unsigned(): ProtectedResourceMetadataTO =
        ProtectedResourceMetadataTO(
            resource = credentialIssuerMetadata.id.externalForm,
            authorizationServers = credentialIssuerMetadata.authorizationServers.map { it.externalForm },
            jwksUri = jwksUri.externalForm,
            scopesSupported = credentialIssuerMetadata.specificCredentialIssuers.map { it.supportedCredential.scope.value }.distinct(),
            bearerMethodsSupported = listOf(BearerMethodTO.HEADER),
            dpopSigningAlgorithmsSupported = dPoPConfigurationProperties.algorithms.map { it.name }.distinct().takeIf { it.isNotEmpty() },
            dpopBoundAccessTokenRequired = false,
        )
}
