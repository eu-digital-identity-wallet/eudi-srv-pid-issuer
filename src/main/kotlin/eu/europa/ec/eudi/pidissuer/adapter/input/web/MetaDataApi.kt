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
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcTypeMetadata
import eu.europa.ec.eudi.sdjwt.vc.Vct
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromStream
import org.springframework.core.io.Resource
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*

val MEDIA_TYPE_APPLICATION_JWT = MediaType("application", "jwt")

class MetaDataApi(
    private val getCredentialIssuerMetaData: GetCredentialIssuerMetaData,
    private val credentialIssuerMetaData: CredentialIssuerMetaData,
    private val typeMetadata: Map<Vct, Resource>,
) {

    val route = coRouter {
        GET(WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetUnsignedCredentialIssuerMetaData()
        }
        GET(WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, accept(MEDIA_TYPE_APPLICATION_JWT)) { _ ->
            handleGetSignedCredentialIssuerMetaData()
        }
        GET(WELL_KNOWN_JWT_VC_ISSUER, accept(MediaType.APPLICATION_JSON)) {
            handleGetJwtVcIssuerMetadata()
        }
        GET(PUBLIC_KEYS, accept(MediaType.APPLICATION_JSON)) {
            handleGetJwtVcIssuerJwks()
        }
        GET(TYPE_METADATA, accept(MediaType.APPLICATION_JSON), ::handleGetSdJwtVcTypeMetadata)
    }

    private suspend fun handleGetUnsignedCredentialIssuerMetaData(): ServerResponse =
        getCredentialIssuerMetaData.unsigned().let { metaData ->
            ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON).json().bodyValueAndAwait(metaData)
        }

    private suspend fun handleGetSignedCredentialIssuerMetaData(): ServerResponse =
        getCredentialIssuerMetaData.signed()?.let { metaData ->
            ServerResponse.ok().contentType(MEDIA_TYPE_APPLICATION_JWT).bodyValueAndAwait(metaData)
        } ?: handleGetUnsignedCredentialIssuerMetaData()

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
        suspend fun Resource.asSdJwtVcTypeMetadata(): SdJwtVcTypeMetadata =
            withContext(Dispatchers.IO) {
                inputStream.use {
                    Json.decodeFromStream(it)
                }
            }

        return typeMetadata[request.vct]
            ?.let { ServerResponse.ok().json().bodyValueAndAwait(it.asSdJwtVcTypeMetadata()) }
            ?: ServerResponse.notFound().buildAndAwait()
    }

    companion object {
        const val WELL_KNOWN_OPENID_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"
        const val WELL_KNOWN_JWT_VC_ISSUER = "/.well-known/jwt-vc-issuer"
        const val PUBLIC_KEYS = "/public_keys.jwks"
        const val TYPE_METADATA = "/type-metadata/{vct}"
    }
}

private val CredentialIssuerMetaData.jwtVcIssuerJwks: JWKSet
    get() = JWKSet(specificCredentialIssuers.mapNotNull { it.publicKey })

private val ServerRequest.vct: Vct
    get() = Vct(pathVariable("vct"))
