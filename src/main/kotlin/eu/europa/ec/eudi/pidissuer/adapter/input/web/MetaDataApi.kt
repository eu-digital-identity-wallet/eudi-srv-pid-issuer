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

import eu.europa.ec.eudi.pidissuer.port.input.GetCredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.GetJwkSet
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json

class MetaDataApi(
    val getCredentialIssuerMetaData: GetCredentialIssuerMetaData,
    val getJwkSet: GetJwkSet,
) {

    val route = coRouter {
        GET(WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetClientIssuerMetaData()
        }
        GET(WELL_KNOWN_JWKS, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetJwtIssuerJwkSet()
        }
    }

    private suspend fun handleGetClientIssuerMetaData(): ServerResponse =
        getCredentialIssuerMetaData().let { metaData -> ServerResponse.ok().json().bodyValueAndAwait(metaData) }

    private suspend fun handleGetJwtIssuerJwkSet(): ServerResponse =
        getJwkSet().let { metaData ->
            ServerResponse.ok().json().bodyValueAndAwait(metaData)
        }

    companion object {
        const val WELL_KNOWN_OPENID_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"

        const val WELL_KNOWN_JWKS = "/.well-known/jwks.json"
    }
}
