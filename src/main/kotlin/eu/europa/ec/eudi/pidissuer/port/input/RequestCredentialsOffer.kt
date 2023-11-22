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
import arrow.core.leftIor
import arrow.core.right
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.*
import kotlinx.serialization.*
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

@Serializable
data class AuthorizationCodeGrantTO(
    @SerialName("issuer_state") val issuerState: String?,
)

@Serializable
data class PreAuthorizedCodeGrantTO(
    @Required @SerialName("pre-authorized_code") val preAuthorizedCode: String,
    @SerialName("user_pin_required") val userPinRequired: Boolean = false,
)

@Serializable
data class GrantsTO(
    @SerialName("authorization_code") val authorizedCodeGrant: AuthorizationCodeGrantTO? = null,
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCodeGrant: PreAuthorizedCodeGrantTO? = null,
)

@Serializable
data class CredentialsOfferTO(
    @Required @SerialName("credential_issuer") val credentialIssuer: String,
    val grants: GrantsTO? = null,
    val credentials: List<String>,
)

@Serializable
data class CredentialsOfferRequestedTO(
    @SerialName("credentials_offer") val credentialsOffer: CredentialsOfferTO,
    @SerialName("url") val uri: String,
)

sealed interface RequestCredentialsOfferError {
    data object Invalid : RequestCredentialsOfferError
}

class RequestCredentialsOffer(
    private val credentialIssuerMetaData: CredentialIssuerMetaData,
) {

    suspend operator fun invoke(): Either<RequestCredentialsOfferError, CredentialsOfferRequestedTO> {
        val credentialsOffer = dummyOffer().toTransferObject()
        return CredentialsOfferRequestedTO(
            credentialsOffer = credentialsOffer,
            uri = credentialsOffer.toURI(null).toString(),
        ).right()
    }

    // TODO This is a dummy method
    //  To be removed
    fun dummyOffer(): CredentialsOffer {
        val metaData = credentialIssuerMetaData
            .credentialsSupported
            .filterIsInstance<MsoMdocMetaData>()
            .find { it.docType == PidMsoMdocV1.docType }!!
        val credentials =
            metaData.scope
                ?.let { listOf(it) }
                ?: emptyList()
        return CredentialsOffer(
            credentialIssuer = credentialIssuerMetaData.id,
            grants = AuthorizationCodeGrant().leftIor(),
            credentials = credentials,
        )
    }
}

//
// Mappings from domain objects to transfer objects
//

private fun Grants.toTransferObject(): GrantsTO {
    fun AuthorizationCodeGrant.toTransferObject() = AuthorizationCodeGrantTO(issuerState)
    fun PreAuthorizedCodeGrant.toTransferObject() = PreAuthorizedCodeGrantTO(
        preAuthorizedCode = preAuthorizedCode.value,
        userPinRequired = userPinRequired,
    )
    return fold(
        fa = { GrantsTO(it.toTransferObject(), null) },
        fb = { GrantsTO(null, it.toTransferObject()) },
        fab = { a, b -> GrantsTO(a.toTransferObject(), b.toTransferObject()) },
    )
}

internal fun CredentialsOffer.toTransferObject(): CredentialsOfferTO = CredentialsOfferTO(
    credentialIssuer = credentialIssuer.externalForm,
    grants = grants?.toTransferObject(),
    credentials = credentials.map { it.value },
)

@OptIn(ExperimentalSerializationApi::class)
private val jsonSupport = Json { explicitNulls = false }

internal fun CredentialsOfferTO.toURI(scheme: String?): URI =
    jsonSupport.encodeToString(this).run {
        val jsonUrlEncoded = URLEncoder.encode(this, StandardCharsets.UTF_8)
        URI.create("${scheme ?: ""}/credential_offer?credential_offer=$jsonUrlEncoded")
    }
