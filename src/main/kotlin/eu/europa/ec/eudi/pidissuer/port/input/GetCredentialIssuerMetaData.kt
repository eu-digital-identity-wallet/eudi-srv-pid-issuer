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
import eu.europa.ec.eudi.pidissuer.port.out.cfg.GetCredentialIssuerContext
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class CredentialIssuerMetaDataTO(
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
) {
    companion object {
        fun fromDomain(m: CredentialIssuerMetaData): CredentialIssuerMetaDataTO = CredentialIssuerMetaDataTO(
            credentialIssuer = m.id.externalForm,
            authorizationServer = m.authorizationServer.externalForm,
            credentialEndpoint = m.credentialEndPoint.externalForm,
            batchCredentialEndpoint = m.batchCredentialEndpoint?.externalForm,
            deferredCredentialEndpoint = m.deferredCredentialEndpoint?.externalForm,
            credentialResponseEncryptionAlgValuesSupported = m.credentialResponseEncryption.fold(emptyList()) {
                it.algorithmsSupported.map { it.toJSONString() }
            },
            credentialResponseEncryptionEncValuesSupported = m.credentialResponseEncryption.fold(emptyList()) {
                it.encryptionMethods.map { it.toJSONString() }
            },
            requireCredentialResponseEncryption = m.credentialResponseEncryption.fold(false) { _ -> true },
            credentialsSupported = m.credentialsSupported.map { credentialMetaDataJson(it) },
        )
    }
}

@OptIn(ExperimentalSerializationApi::class)
private fun credentialMetaDataJson(d: CredentialMetaData): JsonObject = buildJsonObject {
    put("format", d.format.value)
    d.scope?.value?.let { put("scope", it) }
    putJsonArray("cryptographic_binding_methods_supported") {
        addAll(d.cryptographicBindingMethodsSupported.map { it.methodName() })
    }
    putJsonArray("cryptographic_suites_supported") {
        addAll(
            d.cryptographicBindingMethodsSupported.map { method ->
                when (method) {
                    is CryptographicBindingMethod.CoseKey -> method.cryptographicSuitesSupported.map { it.name }
                    is CryptographicBindingMethod.DidAnyMethod -> method.cryptographicSuitesSupported.map { it.name }
                    is CryptographicBindingMethod.DidMethod -> method.cryptographicSuitesSupported.map { it.name }
                    CryptographicBindingMethod.Jwk -> emptyList()
                    is CryptographicBindingMethod.Mso -> method.cryptographicSuitesSupported.map { it.name }
                    is CryptographicBindingMethod.Other -> method.cryptographicSuitesSupported
                }
            }.flatten(),
        )
    }
    when (d) {
        is JwtVcJsonMetaData -> TODO()
        is MsoMdocMetaData -> {
            put("doctype", d.docType)
            if (d.display.isNotEmpty()) {
                putJsonArray("display") {
                    addAll(
                        d.display.map { cd ->
                            buildJsonObject {
                                put("name", cd.name.name)
                                put("locale", cd.name.locale.toString())
                                cd.logo?.let { logo ->
                                    putJsonObject("logo") {
                                        put("url", logo.url.externalForm)
                                        logo.alternativeText?.let { put("alt_text", it) }
                                    }
                                }
                                cd.textColor?.let { put("text_color", it) }
                                cd.backgroundColor?.let { put("background_color", it) }
                            }
                        },
                    )
                }
            }
            putJsonObject("claims") {
                d.msoClaims.forEach { (nameSpace, attributes) ->
                    putJsonObject(nameSpace) {
                        attributes.forEach { attribute ->
                            putJsonObject(attribute.name) {
                                if (attribute.display.isNotEmpty()) {
                                    putJsonArray("display") {
                                        attribute.display.forEach { (locale, value) ->
                                            add(
                                                buildJsonObject {
                                                    put("name", value)
                                                    put("locale", locale.toString())
                                                },
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        is SdJwtVcMetaData -> TODO()
    }
}

class GetCredentialIssuerMetaData(
    val getCredentialIssuerContext: GetCredentialIssuerContext,
) {
    suspend operator fun invoke(): CredentialIssuerMetaDataTO =
        getCredentialIssuerContext().metaData.run(CredentialIssuerMetaDataTO::fromDomain)
}
