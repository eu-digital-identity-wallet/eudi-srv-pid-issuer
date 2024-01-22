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
private data class PreAuthorizedCodeTO(
    @SerialName("pre-authorized_code") @Required val preAuthorizedCode: String,
    @SerialName("user_pin_required") val userPinRequired: Boolean = false,
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
    @SerialName("credentials") @Required val credentials: Set<String>,
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
         * @param credentials the Ids of the Credentials to include in the generated request
         * @param authorizationServers  the configured Authorization Servers
         * @return the resulting TO
         */
        fun forAuthorizationCodeGrant(
            credentialIssuerId: CredentialIssuerId,
            credentials: NonEmptySet<CredentialUniqueId>,
            authorizationServers: List<HttpsUrl>,
        ): CredentialsOfferTO =
            CredentialsOfferTO(
                credentialIssuerId.externalForm,
                credentials.map { it.value }.toSet(),
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
    operator fun invoke(maybeCredentials: Set<CredentialUniqueId>): URI {
        val credentials = maybeCredentials.toNonEmptySetOrNull()
        ensureNotNull(credentials) { MissingCredentialUniqueIds }

        val supportedCredentials = metadata.credentialsSupported.map(CredentialMetaData::id)
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
