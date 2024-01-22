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

import arrow.core.raise.either
import eu.europa.ec.eudi.pidissuer.domain.CredentialUniqueId
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.input.GetSupportedCredentialUniqueIds
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class IssuerUi(
    private val getSupportedCredentialUniqueIds: GetSupportedCredentialUniqueIds,
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
            ::handleDisplayGenerateCredentialsOfferForm,
        )

        // Submit 'generate credentials offer' form
        POST(
            GENERATE_CREDENTIALS_OFFER,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
            ::handleGenerateCredentialsOffer,
        )
    }

    private suspend fun handleDisplayGenerateCredentialsOfferForm(request: ServerRequest): ServerResponse {
        log.info("Displaying 'Generate Credentials Offer' page")
        val supportedCredentialUniqueIds = getSupportedCredentialUniqueIds()
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait("generate-credentials-offer-form", mapOf("credentialIds" to supportedCredentialUniqueIds))
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun handleGenerateCredentialsOffer(request: ServerRequest): ServerResponse {
        log.info("Generating Credentials Offer")
        val credentialIds = request.awaitFormData()["credentialIds"]
            .orEmpty()
            .map(::CredentialUniqueId)
            .toSet()

        return either { createCredentialsOffer(credentialIds) }
            .fold(
                ifLeft = { error ->
                    log.warn("Unable to generated Credentials Offer. Error: {}", error)
                    ServerResponse.badRequest()
                        .contentType(MediaType.TEXT_HTML)
                        .renderAndAwait("generate-credentials-offer-error", mapOf("error" to error::class.java.canonicalName))
                },
                ifRight = { credentialsOffer ->
                    log.info("Successfully generated Credentials Offer. URI: '{}'", credentialsOffer.uri)
                    log.info("Generating QR Code")
                    generateQrCode(credentialsOffer.uri.toString(), Format.PNG, Dimensions(Pixels(300u), Pixels(300u)))
                        .fold(
                            onSuccess = { qrCode ->
                                log.info("Successfully generated QR Code. Displaying generated Credentials Offer.")
                                ServerResponse.ok()
                                    .contentType(MediaType.TEXT_HTML)
                                    .renderAndAwait(
                                        "display-credentials-offer",
                                        mapOf(
                                            "uri" to credentialsOffer.uri.toString(),
                                            "qrCode" to Base64.encode(qrCode),
                                            "qrCodeMediaType" to "image/png",
                                        ),
                                    )
                            },
                            onFailure = { error ->
                                log.error("Unable to generate QR Code.", error)
                                ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                    .contentType(MediaType.TEXT_HTML)
                                    .renderAndAwait(
                                        "generate-credentials-offer-error",
                                        mapOf(
                                            "error" to "unexpected-error",
                                            "exception" to error.stackTraceToString(),
                                        ),
                                    )
                            },
                        )
                },
            )
    }

    companion object {
        const val GENERATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/generate"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}
