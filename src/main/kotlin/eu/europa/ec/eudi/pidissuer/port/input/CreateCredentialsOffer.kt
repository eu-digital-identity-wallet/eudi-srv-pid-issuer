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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.toNonEmptySetOrNull
import com.eygraber.uri.Uri
import com.eygraber.uri.toURI
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import kotlinx.serialization.json.Json
import java.net.URI

/**
 * Generates a Credential Offer and a QR Code in PNG format.
 */
class CreateCredentialsOffer(
    private val metadata: CredentialIssuerMetaData,
    private val credentialsOfferUri: String,
    private val allowedSchemes: NonEmptySet<String>,
) {
    context(_: Raise<Error>)
    operator fun invoke(request: Request): URI =
        context(metadata, credentialsOfferUri, allowedSchemes) {
            validate(request.credentialConfigurationIds)
                .authorizationCodeGrantOffer()
                .toUri(request.customCredentialsOfferUri ?: credentialsOfferUri)
        }

    data class Request(
        val credentialConfigurationIds: Set<CredentialConfigurationId>,
        val customCredentialsOfferUri: String? = null,
    )

    /**
     * Errors that might be returned by [CreateCredentialsOffer].
     */
    sealed interface Error {
        /**
         * No Credentials Unique Ids have been provided.
         */
        data object MissingCredentialConfigurationIds : Error

        /**
         * The provided Credential Unique Ids are not valid.
         */
        data class InvalidCredentialConfigurationIds(
            val ids: NonEmptySet<CredentialConfigurationId>,
        ) : Error

        /**
         * Selected credential configuration ids contain mixing attestation categories.
         */
        data object MultipleAttestationCategories : Error

        /**
         * Indicates the Credentials Offer URI cannot be generated.
         */
        data class InvalidCredentialsOfferUri(
            val cause: Throwable,
        ) : Error
    }
}

context(_: Raise<CreateCredentialsOffer.Error>, metadata: CredentialIssuerMetaData)
private fun validate(unvalidatedIds: Set<CredentialConfigurationId>): NonEmptySet<CredentialConfigurationId> {
    val nonEmptyIds = unvalidatedIds.toNonEmptySetOrNull()
    ensureNotNull(nonEmptyIds) { CreateCredentialsOffer.Error.MissingCredentialConfigurationIds }
    val supportedIds = metadata.credentialConfigurationsSupported.map(CredentialConfiguration::id)
    val unknownIds = nonEmptyIds.filter { it !in supportedIds }.toNonEmptySetOrNull()
    if (unknownIds != null) raise(CreateCredentialsOffer.Error.InvalidCredentialConfigurationIds(unknownIds))
    val supported = metadata.credentialConfigurationsSupported
    val selectedCategories = nonEmptyIds.map { id -> supported.first { it.id == id }.category }.toSet()
    ensure(selectedCategories.size == 1) { CreateCredentialsOffer.Error.MultipleAttestationCategories }
    return nonEmptyIds
}

/**
 * Creates a new [CredentialsOfferTO] for an [Authorization Code Grant][AuthorizationCodeTO] flow.
 * When more than one Authorization Servers are provided, only the first one is included in the resulting
 * [CredentialsOfferTO] as per
 * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1-4.1.2.2).
 *
 * @param this@authorizationCodeGrantOffer the Ids of the Credentials to include in the generated request
 * @return the resulting TO
 */
context(metadata: CredentialIssuerMetaData)
private fun NonEmptySet<CredentialConfigurationId>.authorizationCodeGrantOffer(): CredentialsOfferTO {
    val authorizationCode =
        AuthorizationCodeTO(
            authorizationServer = metadata.authorizationServers.firstOrNull()?.externalForm,
        )
    return CredentialsOfferTO(
        metadata.id.externalForm,
        map(CredentialConfigurationId::value).toSet(),
        GrantsTO(authorizationCode),
    )
}

context(_: Raise<CreateCredentialsOffer.Error.InvalidCredentialsOfferUri>, allowedSchemes: NonEmptySet<String>)
private fun CredentialsOfferTO.toUri(credentialsOfferUri: String): URI =
    catch({
        val uri =
            Uri
                .parse(credentialsOfferUri)
                .buildUpon()
                .appendQueryParameter("credential_offer", Json.encodeToString(this))
                .build()
        require(allowedSchemes.any { it.equals(uri.scheme, ignoreCase = true) }) {
            "credentialsOfferUri must use one of the following schemes: ${allowedSchemes.joinToString()}, got: ${uri.scheme}"
        }

        uri.toURI()
    }) { raise(CreateCredentialsOffer.Error.InvalidCredentialsOfferUri(it)) }
