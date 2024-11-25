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

import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import java.net.URI

class IssuerApi(
    private val createCredentialsOffer: CreateCredentialsOffer,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        POST(
            CREATE_CREDENTIALS_OFFER,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            ::handleCreateCredentialsOffer,
        )
    }

    private suspend fun handleCreateCredentialsOffer(request: ServerRequest): ServerResponse {
        log.info("Generating Credentials Offer")
        val credentialIds = request.awaitBodyOrNull<CreateCredentialsOfferRequestTO>()
            ?.credentialIds
            .orEmpty()
            .map(::CredentialConfigurationId)
            .toSet()

        return createCredentialsOffer(credentialIds).fold(
            ifRight = { credentialsOffer ->
                ServerResponse.ok().json()
                    .bodyValueAndAwait(CreateCredentialsOfferResponseTO.success(credentialsOffer))
                    .also { log.info("Successfully generated Credentials Offer. URI: '{}'", credentialsOffer) }
            },
            ifLeft = { error ->
                ServerResponse.badRequest().json().bodyValueAndAwait(CreateCredentialsOfferResponseTO.error(error))
            },
        )
    }

    companion object {
        const val CREATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/create"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}

@Serializable
private data class CreateCredentialsOfferRequestTO(
    @SerialName("credentialIds") val credentialIds: Set<String>? = null,
)

@Serializable
private data class CreateCredentialsOfferResponseTO(
    @SerialName("credentialsOffer") val credentialsOffer: String? = null,
    @SerialName("error") val error: String? = null,
) {
    companion object {
        fun success(credentialsOffer: URI) =
            CreateCredentialsOfferResponseTO(credentialsOffer = credentialsOffer.toString())

        fun error(error: CreateCredentialsOfferError) =
            CreateCredentialsOfferResponseTO(error = error::class.java.simpleName)
    }
}
