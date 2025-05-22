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
import eu.europa.ec.eudi.pidissuer.port.input.GetTypeMetadata
import eu.europa.ec.eudi.pidissuer.port.input.GetTypeMetadataError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json
import kotlin.jvm.optionals.getOrNull

class MetaDataApi(
    private val getCredentialIssuerMetaData: GetCredentialIssuerMetaData,
    private val credentialIssuerMetaData: CredentialIssuerMetaData,
    private val getTypeMetadata: GetTypeMetadata,
) {

    val route = coRouter {
        GET(WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetClientIssuerMetaData()
        }
        GET(WELL_KNOWN_JWT_VC_ISSUER, accept(MediaType.APPLICATION_JSON)) {
            handleGetJwtVcIssuerMetadata()
        }
        GET(PUBLIC_KEYS, accept(MediaType.APPLICATION_JSON)) {
            handleGetJwtVcIssuerJwks()
        }
        GET(SD_JWT_VC_METADATA, accept(MediaType.APPLICATION_JSON), ::handleGetSdJwtVcTypeMetadata)
    }

    private suspend fun handleGetClientIssuerMetaData(): ServerResponse =
        getCredentialIssuerMetaData().let { metaData -> ServerResponse.ok().json().bodyValueAndAwait(metaData) }

    private suspend fun handleGetJwtVcIssuerMetadata(): ServerResponse =
        ServerResponse.ok()
            .json()
            .bodyValueAndAwait(
                buildJsonObject {
                    put("issuer", JsonPrimitive(credentialIssuerMetaData.id.externalForm))
                    put("jwks", Json.parseToJsonElement(credentialIssuerMetaData.jwtVcIssuerJwks.toString(true)))
                },
            )

    private suspend fun handleGetJwtVcIssuerJwks(): ServerResponse =
        ServerResponse.ok()
            .json()
            .bodyValueAndAwait(credentialIssuerMetaData.jwtVcIssuerJwks.toString(true))

    private suspend fun handleGetSdJwtVcTypeMetadata(request: ServerRequest): ServerResponse {
        val queryParam = request.queryParam("vct")
            .getOrNull<String>() ?: return ServerResponse.badRequest().bodyValueAndAwait("No vct value provided")
        return getTypeMetadata(queryParam).fold(
            ifRight = {
                ServerResponse.ok().json().bodyValueAndAwait(it)
            },
            ifLeft = {
                return when (it) {
                    GetTypeMetadataError.InvalidVct -> ServerResponse.badRequest().bodyValueAndAwait(it)
                    GetTypeMetadataError.UnrecognisedVct -> ServerResponse.badRequest().bodyValueAndAwait(it)
                    GetTypeMetadataError.MetadataIncorrectFormat -> ServerResponse.status(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                    ).bodyValueAndAwait(it)
                    else -> ServerResponse.badRequest().buildAndAwait()
                }
            },
        )
    }

    companion object {
        const val WELL_KNOWN_OPENID_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"
        const val WELL_KNOWN_JWT_VC_ISSUER = "/.well-known/jwt-vc-issuer"
        const val PUBLIC_KEYS = "/public_keys.jwks"
        const val SD_JWT_VC_METADATA = "/type-metadata/sd-jwt-vc"
    }
}

private val CredentialIssuerMetaData.jwtVcIssuerJwks: JWKSet
    get() = JWKSet(specificCredentialIssuers.mapNotNull { it.publicKey })
