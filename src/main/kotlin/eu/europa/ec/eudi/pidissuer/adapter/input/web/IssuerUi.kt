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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import arrow.core.getOrElse
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.appendPath
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import io.ktor.http.URLBuilder
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import kotlin.io.encoding.Base64

class IssuerUi(
    private val credentialsOfferUri: String,
    private val metadata: CredentialIssuerMetaData,
    private val createCredentialsOffer: CreateCredentialsOffer,
    private val generateQrCode: GenerateQqCode,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        // Redirect / to 'generate credentials offer' form
        (GET("") or GET("/")) {
            log.info("Redirecting to {}", GENERATE_CREDENTIALS_OFFER)
            ServerResponse.status(HttpStatus.TEMPORARY_REDIRECT)
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
        val credentialIds = metadata.credentialConfigurationsSupported.map { it.id.value }
        val usefulLinks = createUsefulLinks(metadata.id, metadata.authorizationServers[0])
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "generate-credentials-offer-form",
                mapOf(
                    "credentialIds" to credentialIds,
                    "credentialsOfferUri" to credentialsOfferUri,
                    "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    "usefulLinks" to usefulLinks,
                ),
            )
    }

    private suspend fun handleGenerateCredentialsOffer(request: ServerRequest): ServerResponse {
        log.info("Generating Credentials Offer")
        val formData = request.awaitFormData()
        val credentialIds = formData["credentialIds"]
            .orEmpty()
            .map(::CredentialConfigurationId)
            .toSet()
        val credentialsOfferUri = formData["credentialsOfferUri"]?.firstOrNull { it.isNotBlank() }

        return createCredentialsOffer(credentialIds, credentialsOfferUri).map { credentialsOffer ->
            log.info("Successfully generated Credentials Offer. URI: '{}'", credentialsOffer)

            val qrCode =
                generateQrCode(credentialsOffer, Format.PNG, Dimensions(Pixels(300u), Pixels(300u))).getOrThrow()
            log.info("Successfully generated QR Code. Displaying generated Credentials Offer.")
            ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "display-credentials-offer",
                    mapOf(
                        "uri" to credentialsOffer.toString(),
                        "qrCode" to Base64.encode(qrCode),
                        "qrCodeMediaType" to "image/png",
                        "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    ),
                )
        }.getOrElse { error ->
            log.warn("Unable to generated Credentials Offer. Error: {}", error)
            ServerResponse.badRequest()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-error",
                    mapOf(
                        "error" to error::class.java.canonicalName,
                        "openid4VciVersion" to OpenId4VciSpec.VERSION,
                    ),
                )
        }
    }

    private fun createUsefulLinks(credentialIssuer: CredentialIssuerId, authorizationServer: HttpsUrl): Map<String, String> {
        fun HttpsUrl.wellKnown(path: String): HttpsUrl =
            HttpsUrl.unsafe(
                URLBuilder(value.toExternalForm())
                    .apply {
                        pathSegments = listOf(".well-known", path) + pathSegments.filterNot { it.isBlank() }
                    }.buildString(),
            )

        val credentialIssuerMetadata = credentialIssuer.wellKnown("openid-credential-issuer")
        val authorizationServerMetadata = authorizationServer.wellKnown("oauth-authorization-server")
        val sdJwtVcIssuerMetadata = credentialIssuer.wellKnown("jwt-vc-issuer")
        val pidSdJwtVcTypeMetadata = credentialIssuer.appendPath("/type-metadata/urn:eudi:pid:1")

        return mapOf(
            "credential_issuer_metadata" to credentialIssuerMetadata.externalForm,
            "authorization_server_metadata" to authorizationServerMetadata.externalForm,
            "sdjwt_vc_issuer_metadata" to sdJwtVcIssuerMetadata.externalForm,
            "pid_sdjwt_vc_type_metadata" to pidSdJwtVcTypeMetadata.externalForm,
        )
    }

    companion object {
        const val GENERATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/generate"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}
