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

import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptySetOrNull
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError.InvalidCredentialUniqueIds
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError.MissingCredentialUniqueIds
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

/**
 * Errors that might be returned by [CreateCredentialsOffer].
 */
sealed interface CreateCredentialsOfferError {

    /**
     * No Credentials Unique Ids have been provided.
     */
    data object MissingCredentialUniqueIds : CreateCredentialsOfferError

    /**
     * The provided Credential Unique Ids are not valid.
     */
    data object InvalidCredentialUniqueIds : CreateCredentialsOfferError
}

@Serializable
private data class AuthorizationCodeTO(
    @SerialName("issuer_state") val issuerState: String? = null,
    @SerialName("authorization_server") val authorizationServer: String? = null,
)

@Serializable
private enum class InputModeTO {
    @SerialName("numeric")
    Numeric,

    @SerialName("text")
    Text,
}

@Serializable
private data class TransactionCodeTO(
    @SerialName("input_mode") val inputMode: InputModeTO? = null,
    @SerialName("length") val length: Int? = null,
    @SerialName("description") val description: String? = null,
) {
    init {
        require(length == null || length > 0) {
            "Length if provided should positive number"
        }
        require(description == null || description.length <= 300) {
            "Description is provided should dont exceed 300 characters"
        }
    }
}

@Serializable
private data class PreAuthorizedCodeTO(
    @SerialName("pre-authorized_code") @Required val preAuthorizedCode: String,
    @SerialName("tx_code") val transactionCode: TransactionCodeTO? = null,
    @SerialName("interval") val interval: Long? = null,
    @SerialName("authorization_server") val authorizationServer: String? = null,
)

@Serializable
private data class GrantsTO(
    @SerialName("authorization_code") val authorizationCode: AuthorizationCodeTO? = null,
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCode: PreAuthorizedCodeTO? = null,
)

/**
 * A Credentials Offer as per
 * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1).
 */
@Serializable
private data class CredentialsOfferTO(
    @SerialName("credential_issuer") @Required val credentialIssuer: String,
    @SerialName("credential_configuration_ids") @Required val credentialConfigurationIds: Set<String>,
    @SerialName("grants") val grants: GrantsTO? = null,
) {
    companion object {

        /**
         * Creates a new [CredentialsOfferTO] for an [Authorization Code Grant][AuthorizationCodeTO] flow.
         * When more than one Authorization Servers are provided, only the first one is included in the resulting
         * [CredentialsOfferTO] as per
         * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1-4.1.2.2).
         *
         * @param credentialIssuerId the Id of the Credential Issuer
         * @param credentialConfigurationIds the Ids of the Credentials to include in the generated request
         * @param authorizationServers  the configured Authorization Servers
         * @return the resulting TO
         */
        fun forAuthorizationCodeGrant(
            credentialIssuerId: CredentialIssuerId,
            credentialConfigurationIds: NonEmptySet<CredentialConfigurationId>,
            authorizationServers: List<HttpsUrl>,
        ): CredentialsOfferTO =
            CredentialsOfferTO(
                credentialIssuerId.externalForm,
                credentialConfigurationIds.map { it.value }.toSet(),
                GrantsTO(
                    AuthorizationCodeTO(
                        authorizationServer = authorizationServers
                            .takeIf { it.size > 1 }
                            ?.first()
                            ?.externalForm,
                    ),
                ),
            )
    }
}

/**
 * Generates a Credential Offer and a QR Code in PNG format.
 */
class CreateCredentialsOffer(
    private val metadata: CredentialIssuerMetaData,
    private val credentialsOfferUri: URI,
) {

    context(Raise<CreateCredentialsOfferError>)
    operator fun invoke(maybeCredentials: Set<CredentialConfigurationId>): URI {
        val credentials = maybeCredentials.toNonEmptySetOrNull()
        ensureNotNull(credentials) { MissingCredentialUniqueIds }

        val supportedCredentials = metadata.credentialConfigurationsSupported.map(CredentialConfiguration::id)
        ensure(supportedCredentials.containsAll(credentials)) { InvalidCredentialUniqueIds }

        val credentialsOffer = CredentialsOfferTO.forAuthorizationCodeGrant(
            metadata.id,
            credentials,
            metadata.authorizationServers,
        )

        return UriComponentsBuilder.fromUri(credentialsOfferUri)
            .queryParam("credential_offer", Json.encodeToString(credentialsOffer))
            .build()
            .toUri()
    }
}
