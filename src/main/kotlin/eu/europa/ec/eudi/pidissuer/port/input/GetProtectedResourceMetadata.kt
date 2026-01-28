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
@file:UseSerializers(NonEmptyListSerializer::class)

package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.serialization.NonEmptyListSerializer
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.RFC9728
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

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
    @SerialName(RFC9728.AUTHORIZATION_SERVERS) val authorizationServers: NonEmptyList<String>? = null,
    @SerialName(RFC9728.SCOPES_SUPPORTED) val scopesSupported: NonEmptyList<String>? = null,
    @SerialName(RFC9728.BEARER_METHODS_SUPPORTED) val bearerMethodsSupported: NonEmptyList<BearerMethodTO>? = null,
    @SerialName(RFC9728.DPOP_SIGNING_ALGORITHMS_SUPPORTED) val dpopSigningAlgorithmsSupported: NonEmptyList<String>? = null,
    @SerialName(RFC9728.DPOP_BOUND_ACCESS_TOKEN_REQUIRED) val dpopBoundAccessTokenRequired: Boolean? = null,

)

class GetProtectedResourceMetadata(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val dPoPConfigurationProperties: DPoPConfigurationProperties,
) {
    fun unsigned(): ProtectedResourceMetadataTO =
        ProtectedResourceMetadataTO(
            resource = credentialIssuerMetadata.id.externalForm,
            authorizationServers = credentialIssuerMetadata.authorizationServers.map { it.externalForm }.toNonEmptyListOrNull(),
            scopesSupported = credentialIssuerMetadata.specificCredentialIssuers.map {
                it.supportedCredential.scope.value
            }.distinct().toNonEmptyListOrNull(),
            bearerMethodsSupported = nonEmptyListOf(BearerMethodTO.HEADER),
            dpopSigningAlgorithmsSupported = dPoPConfigurationProperties.algorithms.map { it.name }.distinct().toNonEmptyListOrNull(),
            dpopBoundAccessTokenRequired = false,
        )
}
