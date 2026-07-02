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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import arrow.core.raise.effect
import arrow.core.raise.fold
import com.eygraber.uri.Uri
import eu.europa.ec.eudi.pidissuer.appendPath
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import kotlin.io.encoding.Base64

class IssuerUi(
    private val metadata: CredentialIssuerMetaData,
    private val createCredentialsOffer: CreateCredentialsOffer,
    private val generateQrCode: GenerateQqCode,
) {
    val router: RouterFunction<ServerResponse> =
        coRouter {
            // Redirect / to 'generate credentials offer' form
            (GET("") or GET("/")) {
                log.info("Redirecting to {}", GENERATE_CREDENTIALS_OFFER)
                ServerResponse
                    .status(HttpStatus.TEMPORARY_REDIRECT)
                    .renderAndAwait("redirect:$GENERATE_CREDENTIALS_OFFER")
            }

            // Display 'generate credentials offer' form
            GET(
                GENERATE_CREDENTIALS_OFFER,
                contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
            ) { handleDisplayGenerateCredentialsOfferForm() }

            // Submit 'generate credentials offer' form
            POST(
                GENERATE_CREDENTIALS_OFFER,
                contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
                ::handleGenerateCredentialsOffer,
            )
        }

    private suspend fun handleDisplayGenerateCredentialsOfferForm(): ServerResponse {
        log.info("Displaying 'Generate Credentials Offer' page")
        val credentialConfigurationIds =
            metadata.credentialConfigurationsSupported.groupBy(
                { it.category },
                { it.id.value },
            )
        val usefulLinks = createUsefulLinks(metadata.id, metadata.authorizationServers[0])
        return ServerResponse
            .ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "generate-credentials-offer-form",
                mapOf(
                    "credentialConfigurationIds" to credentialConfigurationIds,
                    "credentialsOfferUri" to createCredentialsOffer.defaultCredentialOfferUri.toString(),
                    "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    "usefulLinks" to usefulLinks,
                ),
            )
    }

    private suspend fun handleGenerateCredentialsOffer(request: ServerRequest): ServerResponse =
        effect {
            log.debug("Generating Credentials Offer")
            val createCredentialOfferRequest = request.createCredentialOfferRequest()
            createCredentialsOffer(createCredentialOfferRequest)
        }.fold(
            transform = { credentialsOfferUri ->
                context(generateQrCode) { credentialsOfferUri.credentialOfferSuccessResponse() }
            },
            recover = { error ->
                log.warn("Unable to generated Credentials Offer. Error: {}", error)
                error.credentialOfferErrorResponse()
            },
        )

    private fun createUsefulLinks(
        credentialIssuer: CredentialIssuerId,
        authorizationServer: HttpsUrl,
    ): Map<String, String> {
        fun HttpsUrl.wellKnown(path: String): HttpsUrl =
            HttpsUrl.unsafe(
                value
                    .buildUpon()
                    .appendPath(".well-known")
                    .appendPath(path)
                    .apply {
                        value.pathSegments
                            .filterNot { it.isBlank() }
                            .forEach { appendPath(it) }
                    }.build()
                    .toString(),
            )

        val credentialIssuerMetadata = credentialIssuer.wellKnown("openid-credential-issuer")
        val protectedResourceMetadata = credentialIssuer.wellKnown("oauth-protected-resource")
        val authorizationServerMetadata = authorizationServer.wellKnown("oauth-authorization-server")
        val sdJwtVcIssuerMetadata = credentialIssuer.wellKnown("jwt-vc-issuer")
        val pidSdJwtVcTypeMetadata = credentialIssuer.appendPath("/type-metadata/urn:eudi:pid:1")
        val learningCredentialSdJwtVcTypeMetadata =
            credentialIssuer.appendPath(
                "/type-metadata/urn:eu.europa.ec.eudi:learning:credential:1",
            )

        return mapOf(
            "credential_issuer_metadata" to credentialIssuerMetadata.externalForm,
            "protected_resource_metadata" to protectedResourceMetadata.externalForm,
            "authorization_server_metadata" to authorizationServerMetadata.externalForm,
            "sdjwt_vc_issuer_metadata" to sdJwtVcIssuerMetadata.externalForm,
            "pid_sdjwt_vc_type_metadata" to pidSdJwtVcTypeMetadata.externalForm,
            "learning_credential_sdjwt_vc_type_metadata" to learningCredentialSdJwtVcTypeMetadata.externalForm,
        )
    }

    companion object {
        const val GENERATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/generate"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}

private suspend fun ServerRequest.createCredentialOfferRequest(): CreateCredentialsOffer.Request {
    val formData = awaitFormData()
    val credentialIds = formData["credentialIds"].orEmpty().map(::CredentialConfigurationId).toSet()
    val credentialsOfferUri = formData["credentialsOfferUri"]?.firstOrNull { it.isNotBlank() }
    return CreateCredentialsOffer.Request(credentialIds, credentialsOfferUri)
}

context(generateQrCode: GenerateQqCode)
private suspend fun Uri.credentialOfferSuccessResponse(): ServerResponse {
    val uri = this@credentialOfferSuccessResponse
    val qrCode = generateQrCode(uri, Format.PNG, Dimensions(Pixels(300u), Pixels(300u)))
    return ServerResponse
        .ok()
        .contentType(MediaType.TEXT_HTML)
        .renderAndAwait(
            "display-credentials-offer",
            mapOf(
                "uri" to uri.toString(),
                "qrCode" to Base64.encode(qrCode),
                "qrCodeMediaType" to "image/png",
            ),
        )
}

private suspend fun CreateCredentialsOffer.Error.credentialOfferErrorResponse(): ServerResponse =
    ServerResponse
        .badRequest()
        .contentType(MediaType.TEXT_HTML)
        .renderAndAwait(
            "generate-credentials-offer-error",
            mapOf(
                "error" to this::class.java.canonicalName,
                "openid4VciVersion" to OpenId4VciSpec.VERSION,
            ),
        )
