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

import arrow.core.Either
import arrow.core.NonEmptySet
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptySetOrNull
import com.eygraber.uri.Uri
import com.eygraber.uri.toURI
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError.InvalidCredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError.MissingCredentialConfigurationIds
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI

/**
 * Errors that might be returned by [CreateCredentialsOffer].
 */
sealed interface CreateCredentialsOfferError {

    /**
     * No Credentials Unique Ids have been provided.
     */
    data object MissingCredentialConfigurationIds : CreateCredentialsOfferError

    /**
     * The provided Credential Unique Ids are not valid.
     */
    data class InvalidCredentialConfigurationId(val id: CredentialConfigurationId) : CreateCredentialsOfferError

    /**
     * Indicates the Credentials Offer URI cannot be generated.
     */
    data class InvalidCredentialsOfferUri(val cause: Throwable) : CreateCredentialsOfferError
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
 * A Credential Offer as per
 * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1).
 */
@Serializable
private data class CredentialsOfferTO(
    @SerialName("credential_issuer") @Required val credentialIssuer: String,
    @SerialName("credential_configuration_ids") @Required val credentialConfigurationIds: Set<String>,
    @SerialName("grants") val grants: GrantsTO? = null,
)

/**
 * Generates a Credential Offer and a QR Code in PNG format.
 */
class CreateCredentialsOffer(
    private val metadata: CredentialIssuerMetaData,
    private val credentialsOfferUri: String,
) {

    operator fun invoke(
        unvalidatedCredentialConfigurationIds: Set<CredentialConfigurationId>,
        customCredentialsOfferUri: String? = null,
    ): Either<CreateCredentialsOfferError, URI> = either {
        val offer = run {
            val credentialConfigurationIds =
                validate(metadata, unvalidatedCredentialConfigurationIds)
            authorizationCodeGrantOffer(metadata, credentialConfigurationIds)
        }

        Either.catch {
            Uri.parse(customCredentialsOfferUri ?: credentialsOfferUri)
                .buildUpon()
                .appendQueryParameter("credential_offer", Json.encodeToString(offer))
                .build()
                .toURI()
        }.getOrElse { raise(CreateCredentialsOfferError.InvalidCredentialsOfferUri(it)) }
    }
}

private fun Raise<CreateCredentialsOfferError>.validate(
    metadata: CredentialIssuerMetaData,
    unvalidatedIds: Set<CredentialConfigurationId>,
): NonEmptySet<CredentialConfigurationId> {
    val nonEmptyIds = unvalidatedIds.toNonEmptySetOrNull()
    ensureNotNull(nonEmptyIds) { MissingCredentialConfigurationIds }
    val supportedIds = metadata.credentialConfigurationsSupported.map(CredentialConfiguration::id)
    nonEmptyIds.forEach { id ->
        ensure(id in supportedIds) { InvalidCredentialConfigurationId(id) }
    }

    return nonEmptyIds
}

/**
 * Creates a new [CredentialsOfferTO] for an [Authorization Code Grant][AuthorizationCodeTO] flow.
 * When more than one Authorization Servers are provided, only the first one is included in the resulting
 * [CredentialsOfferTO] as per
 * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1-4.1.2.2).
 *
 * @param credentialConfigurationIds the Ids of the Credentials to include in the generated request
 * @return the resulting TO
 */
private fun authorizationCodeGrantOffer(
    metadata: CredentialIssuerMetaData,
    credentialConfigurationIds: NonEmptySet<CredentialConfigurationId>,
): CredentialsOfferTO {
    val authorizationCode = AuthorizationCodeTO(
        authorizationServer = metadata.authorizationServers.firstOrNull()?.externalForm,
    )
    return CredentialsOfferTO(
        metadata.id.externalForm,
        credentialConfigurationIds.map(CredentialConfigurationId::value).toSet(),
        GrantsTO(authorizationCode),
    )
}
