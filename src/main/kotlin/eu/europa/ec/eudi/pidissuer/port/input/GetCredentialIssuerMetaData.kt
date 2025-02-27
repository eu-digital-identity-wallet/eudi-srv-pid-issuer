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

import arrow.core.Option
import arrow.core.none
import arrow.core.some
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.jose.GenerateSignedMetadata
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

class GetCredentialIssuerMetaData(
    private val credentialIssuerMetaData: CredentialIssuerMetaData,
    private val generateSignedMetadata: GenerateSignedMetadata?,
) {
    operator fun invoke(): CredentialIssuerMetaDataTO {
        val withoutSignedMetadata = credentialIssuerMetaData.toTransferObject()
        return if (null != generateSignedMetadata) {
            val signedMetadata = generateSignedMetadata.invoke(Json.encodeToJsonElement(withoutSignedMetadata).jsonObject)
            withoutSignedMetadata.copy(signedMetadata = signedMetadata)
        } else {
            withoutSignedMetadata
        }
    }
}

@Serializable
data class CredentialIssuerMetaDataTO(
    @Required @SerialName("credential_issuer")
    val credentialIssuer: String,
    @SerialName("authorization_servers")
    val authorizationServers: List<String>? = null,
    @Required @SerialName("credential_endpoint")
    val credentialEndpoint: String,
    @SerialName("deferred_credential_endpoint")
    val deferredCredentialEndpoint: String? = null,
    @SerialName("notification_endpoint")
    val notificationEndpoint: String? = null,
    @SerialName("nonce_endpoint")
    val nonceEndpoint: String? = null,
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
    @SerialName("batch_credential_issuance")
    val batchCredentialIssuance: BatchCredentialIssuanceTO? = null,
    @SerialName("signed_metadata")
    val signedMetadata: String? = null,
    @SerialName("display")
    val display: List<DisplayTO>? = null,
    @Required @SerialName("credential_configurations_supported")
    val credentialConfigurationsSupported: JsonObject,
    @SerialName("openid4vci_version")
    val openid4VciVersion: String? = null,
) {

    @Serializable
    data class CredentialResponseEncryptionTO(
        @Required @SerialName("alg_values_supported")
        val encryptionAlgorithms: List<String>,
        @Required @SerialName("enc_values_supported")
        val encryptionMethods: List<String>,
        @Required @SerialName("encryption_required")
        val required: Boolean,
    )

    @Serializable
    data class BatchCredentialIssuanceTO(
        @Required @SerialName("batch_size") val batchSize: Int,
    )
}

@Serializable
data class DisplayTO(
    @SerialName("name")
    val name: String? = null,
    @SerialName("locale")
    val locale: String? = null,
    @SerialName("logo")
    val logo: LogoTO? = null,
) {
    @Serializable
    data class LogoTO(
        @Required @SerialName("uri")
        val uri: String,
        @SerialName("alt_text")
        val alternativeText: String? = null,
    )
}

private fun CredentialIssuerMetaData.toTransferObject(): CredentialIssuerMetaDataTO = CredentialIssuerMetaDataTO(
    credentialIssuer = id.externalForm,
    authorizationServers = authorizationServers.map { it.externalForm },
    credentialEndpoint = credentialEndPoint.externalForm,
    deferredCredentialEndpoint = deferredCredentialEndpoint?.externalForm,
    notificationEndpoint = notificationEndpoint?.externalForm,
    nonceEndpoint = nonceEndpoint?.externalForm,
    credentialResponseEncryption = credentialResponseEncryption.toTransferObject().getOrNull(),
    batchCredentialIssuance = when (batchCredentialIssuance) {
        BatchCredentialIssuance.NotSupported -> null
        is BatchCredentialIssuance.Supported -> CredentialIssuerMetaDataTO.BatchCredentialIssuanceTO(batchCredentialIssuance.batchSize)
    },
    signedMetadata = null,
    display = display.map { it.toTransferObject() }.takeIf { it.isNotEmpty() },
    credentialConfigurationsSupported = JsonObject(
        credentialConfigurationsSupported.associate { it.id.value to credentialMetaDataJson(it, batchCredentialIssuance) },
    ),
    openid4VciVersion = OpenId4VciSpec.VERSION,
)

private fun CredentialResponseEncryption.toTransferObject(): Option<CredentialIssuerMetaDataTO.CredentialResponseEncryptionTO> =
    fold(
        ifNotSupported = none(),
        ifOptional = { optional ->
            CredentialIssuerMetaDataTO.CredentialResponseEncryptionTO(
                encryptionAlgorithms = optional.parameters.algorithmsSupported.map { it.name },
                encryptionMethods = optional.parameters.methodsSupported.map { it.name },
                required = false,
            ).some()
        },
        ifRequired = { required ->
            CredentialIssuerMetaDataTO.CredentialResponseEncryptionTO(
                encryptionAlgorithms = required.parameters.algorithmsSupported.map { it.name },
                encryptionMethods = required.parameters.methodsSupported.map { it.name },
                required = true,
            ).some()
        },
    )

private fun CredentialIssuerDisplay.toTransferObject(): DisplayTO =
    DisplayTO(
        name = name,
        locale = locale?.toString(),
        logo = logo?.toTransferObject(),
    )

private fun ImageUri.toTransferObject(): DisplayTO.LogoTO =
    DisplayTO.LogoTO(
        uri = uri.toString(),
        alternativeText = alternativeText,
    )

private fun CredentialConfiguration.format(): Format = when (this) {
    is JwtVcJsonCredentialConfiguration -> JWT_VS_JSON_FORMAT
    is MsoMdocCredentialConfiguration -> MSO_MDOC_FORMAT
    is SdJwtVcCredentialConfiguration -> SD_JWT_VC_FORMAT
}

private fun credentialMetaDataJson(
    d: CredentialConfiguration,
    batchCredentialIssuance: BatchCredentialIssuance,
): JsonObject = buildJsonObject {
    put("format", d.format().value)
    d.scope?.value?.let { put("scope", it) }
    d.cryptographicBindingMethodsSupported.takeIf { it.isNotEmpty() }
        ?.let { cryptographicBindingMethodsSupported ->
            putJsonArray("cryptographic_binding_methods_supported") {
                addAll(cryptographicBindingMethodsSupported.map { it.methodName() })
            }
        }
    d.credentialSigningAlgorithmsSupported.takeIf { it.isNotEmpty() }
        ?.let { credentialSigningAlgorithmsSupported ->
            putJsonArray("credential_signing_alg_values_supported") {
                addAll(credentialSigningAlgorithmsSupported.map { it.name })
            }
        }
    d.proofTypesSupported.takeIf { it != ProofTypesSupported.Empty }
        ?.let { proofTypesSupported ->
            putJsonObject("proof_types_supported") {
                proofTypesSupported.values.forEach {
                    put(it.proofTypeName(), it.toJsonObject())
                }
            }
        }
    when (d) {
        is JwtVcJsonCredentialConfiguration -> TODO()
        is MsoMdocCredentialConfiguration -> d.toTransferObject(batchCredentialIssuance)(this)
        is SdJwtVcCredentialConfiguration -> d.toTransferObject()(this)
    }
}

private fun CryptographicBindingMethod.methodName(): String =
    when (this) {
        is CryptographicBindingMethod.Jwk -> "jwk"
        is CryptographicBindingMethod.CoseKey -> "cose_key"
        is CryptographicBindingMethod.DidMethod -> "did:$didMethod"
        is CryptographicBindingMethod.DidAnyMethod -> "DID"
    }

private fun ProofType.proofTypeName(): String =
    when (this) {
        is ProofType.Jwt -> "jwt"
    }

private fun ProofType.toJsonObject(): JsonObject =
    buildJsonObject {
        when (this@toJsonObject) {
            is ProofType.Jwt -> {
                putJsonArray("proof_signing_alg_values_supported") {
                    addAll(signingAlgorithmsSupported.map { it.name })
                }
                if (keyAttestation is KeyAttestation.Required) {
                    putJsonObject("key_attestations_required") {
                        keyAttestation.keyStorage?.let { keyStorage ->
                            putJsonArray("key_storage") {
                                addAll(keyStorage.map { it.value })
                            }
                        }
                        keyAttestation.useAuthentication?.let { userAuthentication ->
                            putJsonArray("user_authentication") {
                                addAll(userAuthentication.map { it.value })
                            }
                        }
                    }
                }
            }
        }
    }

internal fun MsoMdocCredentialConfiguration.toTransferObject(
    batchCredentialIssuance: BatchCredentialIssuance,
): JsonObjectBuilder.() -> Unit = {
    put("doctype", docType)
    if (display.isNotEmpty()) {
        putJsonArray("display") {
            addAll(display.map { it.toTransferObject() })
        }
    }
    if (policy != null) {
        putJsonObject("policy") {
            put("one_time_use", policy.oneTimeUse)
            if (batchCredentialIssuance is BatchCredentialIssuance.Supported) {
                put("batch_size", batchCredentialIssuance.batchSize)
            }
        }
    }

    if (claims.isNotEmpty()) {
        putJsonArray("claims") {
            addAll(claims.flatMap { it.toJsonObjects() })
        }
    }
}

internal fun SdJwtVcCredentialConfiguration.toTransferObject(): JsonObjectBuilder.() -> Unit = {
    if (display.isNotEmpty()) {
        putJsonArray("display") {
            addAll(display.map { it.toTransferObject() })
        }
    }
    put("vct", type.value)
    if (claims.isNotEmpty()) {
        putJsonArray("claims") {
            addAll(claims.flatMap { it.toJsonObjects() })
        }
    }
}

internal fun CredentialDisplay.toTransferObject(): JsonObject = buildJsonObject {
    put("name", name.name)
    put("locale", name.locale.toString())
    logo?.let { logo ->
        putJsonObject("logo") {
            put("uri", logo.uri.toString())
            logo.alternativeText?.let { put("alt_text", it) }
        }
    }
    description?.let { put("description", it) }
    backgroundColor?.let { put("background_color", it) }
    backgroundImage?.let { backgroundImage ->
        putJsonObject("background_image") {
            put("uri", backgroundImage.uri.toString())
        }
    }
    textColor?.let { put("text_color", it) }
}

private fun ClaimDefinition.toJsonObjects(): List<JsonObject> {
    fun ClaimDefinition.toJsonObject(): JsonObject = buildJsonObject {
        put("path", Json.encodeToJsonElement(path))
        mandatory?.let { put("mandatory", it) }
        if (display.isNotEmpty()) {
            put("display", display.toTransferObject())
        }
    }

    fun ClaimDefinition.flatten(): List<ClaimDefinition> {
        tailrec fun flatten(accumulator: List<ClaimDefinition>, remainder: List<ClaimDefinition>): List<ClaimDefinition> =
            if (remainder.isEmpty()) {
                accumulator
            } else {
                val head = remainder.first()
                val tail = remainder.drop(1)
                flatten(accumulator + head, head.nested + tail)
            }
        return flatten(emptyList(), listOf(this))
    }

    return flatten().map { it.toJsonObject() }
}

internal fun Display.toTransferObject(): JsonArray =
    map { (locale, value) ->
        buildJsonObject {
            put("name", value)
            put("locale", locale.toString())
        }
    }.run { JsonArray(this) }
