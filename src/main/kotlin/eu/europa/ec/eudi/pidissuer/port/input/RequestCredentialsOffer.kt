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

import arrow.core.leftIor
import arrow.core.raise.Raise
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.domain.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.port.out.cfg.GetCredentialIssuerContext
import kotlinx.serialization.*
import kotlinx.serialization.json.*
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
    val grants: GrantsTO,
    val credentials: List<JsonElement>,
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
    private val getCredentialIssuerContext: GetCredentialIssuerContext,
) {

    context(Raise<RequestCredentialsOfferError>)
    suspend operator fun invoke(): CredentialsOfferRequestedTO {
        val credentialsOffer = dummyOffer().toTransferObject()
        return CredentialsOfferRequestedTO(
            credentialsOffer = credentialsOffer,
            uri = credentialsOffer.toURI(null).toString(),
        )
    }

    fun dummyOffer(): CredentialsOffer {
        val ctx = getCredentialIssuerContext()
        val p = ctx.metaData.credentialsSupported.filterIsInstance<MsoMdocMetaData>()
            .find { it.docType == PidMsoMdocV1.docType }!!
        return CredentialsOffer.single(
            credentialIssuer = ctx.metaData.id,
            grants = AuthorizationCodeGrant().leftIor(),
            credentialOffer = MsoMdocCredentialOffer(p.docType),
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

@OptIn(ExperimentalSerializationApi::class)
private fun CredentialOffer.toTransferObject(): JsonElement {
    fun CredentialOfferByScope.toTransferObject() = JsonPrimitive(value.value)
    fun MsoMdocCredentialOffer.toTransferObject() = buildJsonObject {
        put("format", MSO_MDOC_FORMAT)
        put("doctype", docType)
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun JwtVcJsonCredentialOffer.toTransferObject() = buildJsonObject {
        put("format", JWT_VS_JSON_FORMAT)
        putJsonArray("type") { addAll(type) }
    }
    return when (this) {
        is CredentialOfferByScope -> toTransferObject()
        is JwtVcJsonCredentialOffer -> toTransferObject()
        is MsoMdocCredentialOffer -> toTransferObject()
    }
}

internal fun CredentialsOffer.toTransferObject(): CredentialsOfferTO = CredentialsOfferTO(
    credentialIssuer = credentialIssuer.externalForm,
    grants = grants.toTransferObject(),
    credentials = credentials.map { it.toTransferObject() },
)

@OptIn(ExperimentalSerializationApi::class)
private val jsonSupport = Json { explicitNulls = false }

internal fun CredentialsOfferTO.toURI(scheme: String?): URI {
    val json: String = jsonSupport.encodeToString(this)
    return URI.create(
        "${scheme ?: ""}/credential_offer?credential_offer=${
            URLEncoder.encode(
                json,
                StandardCharsets.UTF_8,
            )
        }",
    )
}
