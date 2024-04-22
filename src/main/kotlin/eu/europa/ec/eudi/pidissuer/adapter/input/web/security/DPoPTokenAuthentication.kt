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
package eu.europa.ec.eudi.pidissuer.adapter.input.web.security

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import java.net.URI

/**
 * A DPoP authentication token.
 */
class DPoPTokenAuthentication private constructor(
    val dpop: SignedJWT,
    val accessToken: DPoPAccessToken,
    val method: HttpMethod,
    val uri: URI,
    private val _principal: OAuth2AuthenticatedPrincipal?,
) : AbstractAuthenticationToken(_principal?.authorities ?: emptySet()) {
    init {
        isAuthenticated = _principal != null
    }

    override fun getCredentials(): Pair<SignedJWT, DPoPAccessToken> = dpop to accessToken
    override fun getPrincipal(): OAuth2AuthenticatedPrincipal? = _principal
    override fun getName(): String = _principal?.attributes?.get("username") as? String ?: ""

    /**
     * Gets a new _authenticated_ [DPoPTokenAuthentication] that contains the provided [principal].
     */
    fun authenticate(principal: OAuth2AuthenticatedPrincipal): DPoPTokenAuthentication =
        DPoPTokenAuthentication(dpop, accessToken, method, uri, principal)

    companion object {

        /**
         * Creates a new _unauthenticated_ [DPoPTokenAuthentication].
         */
        fun unauthenticated(
            dpop: SignedJWT,
            accessToken: DPoPAccessToken,
            method: HttpMethod,
            uri: URI,
        ): DPoPTokenAuthentication = DPoPTokenAuthentication(dpop, accessToken, method, uri, null)
    }
}
