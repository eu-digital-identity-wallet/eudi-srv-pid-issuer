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

import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.GetCredentialIssuerMetaData
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json

class MetaDataApi(
    private val getCredentialIssuerMetaData: GetCredentialIssuerMetaData,
    private val credentialIssuerMetaData: CredentialIssuerMetaData,
) {

    val route = coRouter {
        GET(WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetClientIssuerMetaData()
        }
        GET(WELL_KNOWN_JWKS, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetJwtIssuerJwkSet()
        }
        ((GET(WELL_KNOWN_JWT_ISSUER) or GET(PUBLIC_KEYS)) and accept(MediaType.APPLICATION_JSON)) {
            handleGetJwtIssuer()
        }
    }

    private suspend fun handleGetClientIssuerMetaData(): ServerResponse =
        getCredentialIssuerMetaData().let { metaData -> ServerResponse.ok().json().bodyValueAndAwait(metaData) }

    private suspend fun handleGetJwtIssuerJwkSet(): ServerResponse =
        TODO()

    private suspend fun handleGetJwtIssuer(): ServerResponse {
        val jwks = JWKSet(credentialIssuerMetaData.specificCredentialIssuers.mapNotNull { it.publicKey })
        val response = buildJsonObject {
            put("issuer ", JsonPrimitive(credentialIssuerMetaData.id.externalForm))
            put("jwks ", Json.parseToJsonElement(jwks.toString(true)))
        }
        return ServerResponse.ok()
            .json()
            .bodyValue(response)
            .awaitSingle()
    }

    companion object {
        const val WELL_KNOWN_OPENID_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"
        const val WELL_KNOWN_JWKS = "/.well-known/jwks.json"
        const val WELL_KNOWN_JWT_ISSUER = "/.well-known/jwt-issuer"
        const val PUBLIC_KEYS = "/public_keys.jwks"
    }
}
