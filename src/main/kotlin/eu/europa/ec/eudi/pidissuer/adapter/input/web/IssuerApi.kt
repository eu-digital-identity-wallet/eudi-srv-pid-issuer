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
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import java.net.URI

class IssuerApi(
    private val createCredentialsOffer: CreateCredentialsOffer,
) {
    val router: RouterFunction<ServerResponse> =
        coRouter {
            POST(
                CREATE_CREDENTIALS_OFFER,
                contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
                ::handleCreateCredentialsOffer,
            )
        }

    private suspend fun handleCreateCredentialsOffer(request: ServerRequest): ServerResponse =
        effect {
            log.info("Generating Credentials Offer")
            val createCredentialsOfferRequest = request.createCredentialOfferRequest()
            createCredentialsOffer(createCredentialsOfferRequest)
        }.fold(
            transform = { createCredentialsOfferUri -> createCredentialsOfferUri.credentialOfferSuccessResponse() },
            recover = { error -> error.credentialOfferErrorResponse() },
        )

    companion object {
        const val CREATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/create"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}

private suspend fun ServerRequest.createCredentialOfferRequest(): CreateCredentialsOffer.Request {
    @Serializable
    data class CreateCredentialsOfferRequestTO(
        @SerialName("credentialIds") val credentialIds: Set<String>? = null,
    ) {
        fun asRequest() = CreateCredentialsOffer.Request(credentialIds.orEmpty().map(::CredentialConfigurationId).toSet())
    }
    return awaitBody<CreateCredentialsOfferRequestTO>().asRequest()
}

private suspend fun Uri.credentialOfferSuccessResponse(): ServerResponse {
    val dto = CreateCredentialsOfferResponseTO.success(this)
    return ServerResponse
        .ok()
        .json()
        .bodyValueAndAwait(dto)
}

private suspend fun CreateCredentialsOffer.Error.credentialOfferErrorResponse(): ServerResponse {
    val dto = CreateCredentialsOfferResponseTO.error(this)
    return ServerResponse.badRequest().json().bodyValueAndAwait(dto)
}

@Serializable
private data class CreateCredentialsOfferResponseTO(
    @SerialName("credentialsOffer") val credentialsOffer: String? = null,
    @SerialName("error") val error: String? = null,
) {
    companion object {
        fun success(credentialsOffer: Uri) = CreateCredentialsOfferResponseTO(credentialsOffer = credentialsOffer.toString())

        fun error(error: CreateCredentialsOffer.Error) = CreateCredentialsOfferResponseTO(error = error::class.java.simpleName)
    }
}
