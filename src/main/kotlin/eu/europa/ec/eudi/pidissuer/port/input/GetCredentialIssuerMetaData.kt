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

import eu.europa.ec.eudi.pidissuer.domain.*
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

class GetCredentialIssuerMetaData(
    val credentialIssuerMetaData: CredentialIssuerMetaData,
) {
    suspend operator fun invoke(): CredentialIssuerMetaDataTO =
        coroutineScope {
            credentialIssuerMetaData.toTransferObject()
        }
}

@Serializable
public data class CredentialIssuerMetaDataTO(
    @Required @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("authorization_server") val authorizationServer: String? = null,
    @Required @SerialName("credential_endpoint") val credentialEndpoint: String,
    @SerialName("batch_credential_endpoint") val batchCredentialEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("credential_response_encryption_alg_values_supported") val credentialResponseEncryptionAlgValuesSupported: List<String> =
        emptyList(),
    @SerialName("credential_response_encryption_enc_values_supported") val credentialResponseEncryptionEncValuesSupported: List<String> =
        emptyList(),
    @SerialName("require_credential_response_encryption") val requireCredentialResponseEncryption: Boolean = false,
    @Required @SerialName("credentials_supported") val credentialsSupported: List<JsonObject>,
)

private fun CredentialIssuerMetaData.toTransferObject(): CredentialIssuerMetaDataTO = CredentialIssuerMetaDataTO(
    credentialIssuer = id.externalForm,
    authorizationServer = authorizationServer.externalForm,
    credentialEndpoint = credentialEndPoint.externalForm,
    batchCredentialEndpoint = batchCredentialEndpoint?.externalForm,
    deferredCredentialEndpoint = deferredCredentialEndpoint?.externalForm,
    credentialResponseEncryptionAlgValuesSupported = credentialResponseEncryption.fold(emptyList()) { required ->
        required.algorithmsSupported.map { it.toJSONString() }
    },
    credentialResponseEncryptionEncValuesSupported = credentialResponseEncryption.fold(emptyList()) { required ->
        required.encryptionMethods.map { it.toJSONString() }
    },
    requireCredentialResponseEncryption = credentialResponseEncryption.fold(false) { _ -> true },
    credentialsSupported = credentialsSupported.map { credentialMetaDataJson(it) },
)

@OptIn(ExperimentalSerializationApi::class)
private fun credentialMetaDataJson(d: CredentialMetaData): JsonObject = buildJsonObject {
    put("format", d.format.value)
    d.scope?.value?.let { put("scope", it) }
    putJsonArray("cryptographic_binding_methods_supported") {
        addAll(d.cryptographicBindingMethodsSupported.map { it.methodName() })
    }
    putJsonArray("cryptographic_suites_supported") {
        addAll(d.cryptographicSuitesSupported().map { it.name })
    }
    when (d) {
        is JwtVcJsonMetaData -> TODO()
        is MsoMdocMetaData -> d.toTransferObject(false)(this)
        is SdJwtVcMetaData -> d.toTransferObject(false)(this)
    }
}

@OptIn(ExperimentalSerializationApi::class)
internal fun MsoMdocMetaData.toTransferObject(isOffer: Boolean): JsonObjectBuilder.() -> Unit = {
    put("doctype", docType)
    if (!isOffer) {
        if (display.isNotEmpty()) {
            putJsonArray("display") {
                addAll(display.map { it.toTransferObject() })
            }
        }

        putJsonObject("claims") {
            msoClaims.forEach { (nameSpace, attributes) ->
                putJsonObject(nameSpace) {
                    attributes.forEach { attribute -> attribute.toTransferObject(this) }
                }
            }
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
internal fun SdJwtVcMetaData.toTransferObject(isOffer: Boolean): JsonObjectBuilder.() -> Unit = {
    if (!isOffer) {
        if (display.isNotEmpty()) {
            putJsonArray("display") {
                addAll(display.map { it.toTransferObject() })
            }
        }
    }
    putJsonObject("credential_definition") {
        put("type", type.value)
        if (!isOffer) {
            putJsonObject("claims") {
                claims.forEach { attribute -> attribute.toTransferObject(this) }
            }
        }
    }
}

internal fun CredentialDisplay.toTransferObject(): JsonObject = buildJsonObject {
    put("name", name.name)
    put("locale", name.locale.toString())
    logo?.let { logo ->
        putJsonObject("logo") {
            put("url", logo.url.externalForm)
            logo.alternativeText?.let { put("alt_text", it) }
        }
    }
    textColor?.let { put("text_color", it) }
    backgroundColor?.let { put("background_color", it) }
}

internal val AttributeDetails.toTransferObject: JsonObjectBuilder.() -> Unit
    get() = {
        putJsonObject(name) {
            put("mandatory", mandatory)
            valueType?.let { put("value_type", it) }
            if (display.isNotEmpty()) {
                put("display", display.toTransferObject())
            }
        }
    }

internal fun Display.toTransferObject(): JsonArray =
    map { (locale, value) ->
        buildJsonObject {
            put("name", value)
            put("locale", locale.toString())
        }
    }.run { JsonArray(this) }
