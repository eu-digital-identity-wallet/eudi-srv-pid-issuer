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
package eu.europa.ec.eudi.pidissuer

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.OIDCScopeValue
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse
import com.nimbusds.openid.connect.sdk.UserInfoRequest
import com.nimbusds.openid.connect.sdk.UserInfoResponse
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.web.reactive.function.client.WebClient
import java.net.URI

@Disabled
class KeycloakOauthClient {

    companion object {
        val issuerURI = URI("http://localhost:8180/realms/pid-issuer-realm")

        // a public client:
        val clientID = ClientID("idp-issuer-srv")

        // with redirect URI:
        // val clientRedirectURI = URI.create("http://eudiw/oidc-callback")
        // use OAuth out-of-band (OOB), also referred to as the manual copy/paste option
        val clientRedirectURI = URI.create("urn:ietf:wg:oauth:2.0:oob")

        val SCOPE_PID_MSO_MDOC = "eu.europa.ec.eudiw.pid_mso_mdoc"
        val SCOPE_PID_SDJWT_VC = "eu.europa.ec.eudiw.pid_sd-jwt-vc"
        val scope = Scope(OIDCScopeValue.OPENID.value, SCOPE_PID_MSO_MDOC, SCOPE_PID_SDJWT_VC)

        // for development only:
        val state = State("mystate")
        val codeVerifier =
            CodeVerifier("m4_D5GD3NRdbF0HPXwotNSCljIgpbvx48bQVqvlCtNw") // <--- PKCE CodeVerifier() uses SecureRandom
    }

    @Test
    fun testAsMetadata() {
        val authorizationServerMetadata = getAuthorizationServerMetadata()
        println("contents = $authorizationServerMetadata")
    }

    @Order(1)
    @Test
    fun testGetAuthorizationCode() { getAuthorizationCodeUsingPAR() }

    @Order(3)
    @ParameterizedTest()
    @ValueSource(
        strings = [
            "86b19f4a-a335-4d84-b377-5b8508ed3df4.6fbabe22-f053-4717-b188-5fadb884bfdf.96c77216-b349-4fbc-b9c2-ba22240de17a",
        ],
    )
    fun testGetAccessTokenByAuthorizationCode(authorizationCode: String) { getAccessTokenByAuthorizationCode(authorizationCode) }
    // the scopes will be the ones requested in the PAR request + the default scopes at client "Wallet"/Client Scopes that
    // have also the "Include in token scope" flag set to true

    @ParameterizedTest()
    @Order(4)
    @ValueSource(
        strings = [
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMRjAtdVltNDJWRW5JeDhXa0lMcHpwdVoxRHNYanpmeHVPa1R4YXlMR0xNIn0" +
                ".eyJleHAiOjE2OTY0MTM3NDcsImlhdCI6MTY5NjQxMzQ0NywiYXV0aF90aW1lIjoxNjk2NDEyODc1LCJqdGkiOiI4Zjc4NTIzMi02NjRkLTQ4MT" +
                "UtYmFlNC1kMTZhMjIxYTA0ZWIiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsL3JlYWxtcy9ldWRpdyIsImF1ZCI6ImFjY291b" +
                "nQiLCJzdWIiOiJhYjg0YmUxMS1mOTUyLTQzY2EtYTUxYS0yYjFjMWQzMDU2MGQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3YWxsZXQi" +
                "LCJzZXNzaW9uX3N0YXRlIjoiNmZiYWJlMjItZjA1My00NzE3LWIxODgtNWZhZGI4ODRiZmRmIiwiYWNyIjoiMCIsImFsbG93ZWQtb3J" +
                "pZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWV1ZGl3Iiwib2ZmbGluZV9hY2Nlc3MiLC" +
                "JwaWQtaG9sZGVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hb" +
                "mFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwaWQtbXNv" +
                "LW1kb2Mtc2NvcGUgcGlkLXNkand0LXZjLXNjb3BlIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI2ZmJhYmUyMi1mMDUzLTQ3MTctYjE4OC0" +
                "1ZmFkYjg4NGJmZGYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImZpcnN0bmFtZWEgbGFzdG5hbWVhIiwicHJlZmVycmVkX3" +
                "VzZXJuYW1lIjoidXNlcmEiLCJnaXZlbl9uYW1lIjoiZmlyc3RuYW1lYSIsImZhbWlseV9uYW1lIjoibGFzdG5hbWVhIn0.loAgbvSjh" +
                "hkJ8vYr6pAri1qkgkOfCU9s8-AeA-TqcZluZqYingnULTnAzZtJIx5BG-JadZookJqb4qTuYVAZmDEljHdoTckL9FepUGzbHWo-QEu_" +
                "gDdc_G2pTOADwWjTxLR1VcOyOSmUkgKo0Q1zdsOrwc7XLGQM7VTLpDdP8Q6W89ubLGJTZXb9rYfTs0Q11blnm-r4E6Fq29225tUq1BV" +
                "KQLXoiGg2cDBUOXubeRvFqu83P6tFBrqSbpL3yTYZN1wlJ2i6Go8shBXs-7t0pqD7fPy3x0uKYB_4gqj4Udzu4hTN3kLY6gWGHVYpPs" +
                "fryzXHe3xo5vKuqTvo-ksBDA",
        ],
    )
    fun testGetUserInfo(accessToken: String) {
        println("testGetUserInfo")
        val userInfoEndpoint = getAuthorizationServerMetadata()?.userInfoEndpointURI
        val token = BearerAccessToken(accessToken)
        // Make the request
        val httpResponse = UserInfoRequest(userInfoEndpoint, token)
            .toHTTPRequest()
            .send()
        // Parse the response
        val userInfoResponse = UserInfoResponse.parse(httpResponse)
        assert(userInfoResponse.indicatesSuccess()) {
            "UserInfoRequest failed, status code: ${httpResponse.statusCode}, " +
                "status message: ${httpResponse.statusMessage}, content: ${httpResponse.content}"
        }
        val userInfo = userInfoResponse.toSuccessResponse().userInfo
        println("userInfo = $userInfo")
    }

    @ParameterizedTest()
    @Order(4)
    @ValueSource(
        strings = [
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMRjAtdVltNDJWRW5JeDhXa0lMcHpwdVoxRHNYanpmeHVPa1R4YXlMR0xNIn0" +
                ".eyJleHAiOjE2OTY0MTM3NDcsImlhdCI6MTY5NjQxMzQ0NywiYXV0aF90aW1lIjoxNjk2NDEyODc1LCJqdGkiOiI4Zjc4NTIzMi02NjRkLTQ4MT" +
                "UtYmFlNC1kMTZhMjIxYTA0ZWIiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsL3JlYWxtcy9ldWRpdyIsImF1ZCI6ImFjY291b" +
                "nQiLCJzdWIiOiJhYjg0YmUxMS1mOTUyLTQzY2EtYTUxYS0yYjFjMWQzMDU2MGQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3YWxsZXQi" +
                "LCJzZXNzaW9uX3N0YXRlIjoiNmZiYWJlMjItZjA1My00NzE3LWIxODgtNWZhZGI4ODRiZmRmIiwiYWNyIjoiMCIsImFsbG93ZWQtb3J" +
                "pZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWV1ZGl3Iiwib2ZmbGluZV9hY2Nlc3MiLC" +
                "JwaWQtaG9sZGVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hb" +
                "mFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwaWQtbXNv" +
                "LW1kb2Mtc2NvcGUgcGlkLXNkand0LXZjLXNjb3BlIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI2ZmJhYmUyMi1mMDUzLTQ3MTctYjE4OC0" +
                "1ZmFkYjg4NGJmZGYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImZpcnN0bmFtZWEgbGFzdG5hbWVhIiwicHJlZmVycmVkX3" +
                "VzZXJuYW1lIjoidXNlcmEiLCJnaXZlbl9uYW1lIjoiZmlyc3RuYW1lYSIsImZhbWlseV9uYW1lIjoibGFzdG5hbWVhIn0.loAgbvSjh" +
                "hkJ8vYr6pAri1qkgkOfCU9s8-AeA-TqcZluZqYingnULTnAzZtJIx5BG-JadZookJqb4qTuYVAZmDEljHdoTckL9FepUGzbHWo-QEu_" +
                "gDdc_G2pTOADwWjTxLR1VcOyOSmUkgKo0Q1zdsOrwc7XLGQM7VTLpDdP8Q6W89ubLGJTZXb9rYfTs0Q11blnm-r4E6Fq29225tUq1BV" +
                "KQLXoiGg2cDBUOXubeRvFqu83P6tFBrqSbpL3yTYZN1wlJ2i6Go8shBXs-7t0pqD7fPy3x0uKYB_4gqj4Udzu4hTN3kLY6gWGHVYpPs" +
                "fryzXHe3xo5vKuqTvo-ksBDA",
        ],
    )
    fun testAccessResourceServer(accessToken: String) {
        println("testGetUserInfo")
        val userInfoEndpoint = getAuthorizationServerMetadata()?.userInfoEndpointURI
        // val resourceServerEndpoint = URI("http://localhost:8083/api/v1/user")
        val resourceServerEndpoint = URI("http://localhost:8082/wallet/credentialEndpoint")
        val token = BearerAccessToken(accessToken)
        val wc = WebClient.builder().build()
        val response = wc.get()
            .uri(resourceServerEndpoint)
            .header("Authorization", "Bearer $accessToken")
            .retrieve()
            .bodyToMono(String::class.java)
            .block()
        println("response = $response")
    }

    @Order(9)
    @ParameterizedTest()
    @ValueSource(
        strings = [
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMRjAtdVltNDJWRW5JeDhXa0lMcHpwdVoxRHNYanpmeHVPa1R4YXlMR0xNIn0." +
                "eyJleHAiOjE2OTYzMjc2NDUsImlhdCI6MTY5NjMyNzM0NSwiYXV0aF90aW1lIjoxNjk2MzI2OTI2LCJqdGkiOiIyMGE4OGU4NC01MDE2LTQ3NTMt" +
                "ODk3YS1kMjdkYTE3NzI4NzUiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsL3JlYWxtcy9ldWRpdyIsImF1ZCI6ImFjY291bnQi" +
                "LCJzdWIiOiJhYjg0YmUxMS1mOTUyLTQzY2EtYTUxYS0yYjFjMWQzMDU2MGQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3YWxsZXQiLCJz" +
                "ZXNzaW9uX3N0YXRlIjoiYTllM2E4NTctYThmNS00OTc4LWEyOTItMjUzYmRhYzk4MDlmIiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lu" +
                "cyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWV1ZGl3Iiwib2ZmbGluZV9hY2Nlc3MiLCJwaWQt" +
                "aG9sZGVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1h" +
                "Y2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwaWQtbXNvLW1kb2Mt" +
                "c2NvcGUgcGlkLXNkand0LXZjLXNjb3BlIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJhOWUzYTg1Ny1hOGY1LTQ5NzgtYTI5Mi0yNTNiZGFj" +
                "OTgwOWYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImZpcnN0bmFtZWEgbGFzdG5hbWVhIiwicHJlZmVycmVkX3VzZXJuYW1l" +
                "IjoidXNlcmEiLCJnaXZlbl9uYW1lIjoiZmlyc3RuYW1lYSIsImZhbWlseV9uYW1lIjoibGFzdG5hbWVhIn0.GjHz63b5ZEdCdY_Qo4DF" +
                "bYW8zWry_9Nr_Y09IIPs3RNaS_9-ijyBrIEBKhVIPvi5ETTyKlfBaLz6APhR9UyGg1bPPRvQ5Q_1rZhLH6YKFz4LTF870AYtBsNSqlNE" +
                "QXYhU6lPcsBrA3a3f_NDvYmhrp7iSCZQYZtlXaf3HS6Fd7-mLo5evbq_xajYWnrieDJhhCkj2cpd4RdSZ4j_UuH9_09QlPxiBxsu2oJI" +
                "jVmCIWyyOpzJvHajq0hG6SlhCpi-_knd-AfLCUr--8xHHGwPewylfFrVlx9p-L9TJUv2qJc7B3ILzwW6npmwMMhtKlzTbHMoOdw0G05M" +
                "XrD1GKXVqg",
        ],
    )
    fun testGetAccessToken(accessToken: String) {
        println("testGetAccessToken")
        printAccessToken(accessToken)
    }

    @Test
    fun testPrintAccessToken() {
        val atoken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMRjAtdVltNDJWRW5JeDhXa0lMcHpwdVoxRHNYanpmeHVPa1" +
            "R4YXlMR0xNIn0.eyJleHAiOjE2OTU5NzIxNzcsImlhdCI6MTY5NTk3MTg3NywiYXV0aF90aW1lIjoxNjk1OTY5NzIzLCJqdGkiOiI4O" +
            "DkzOGMxZS1jMzc4LTQ0ZTMtODk0Mi1hMTE0M2NlYWM0ZWIiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsL3JlYWxtcy9ldWRp" +
            "dyIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhYjg0YmUxMS1mOTUyLTQzY2EtYTUxYS0yYjFjMWQzMDU2MGQiLCJ0eXAiOiJCZWFyZXI" +
            "iLCJhenAiOiJ3YWxsZXQiLCJzZXNzaW9uX3N0YXRlIjoiMTFlYTRkYTMtMThjOS00ZTk1LWExNDktNjQ4NGRmYmEyYWFjIiwiYWNyIj" +
            "oiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWV1ZGl3Iiwib" +
            "2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsi" +
            "bWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2Z" +
            "pbGUgZW1haWwgb2ZmbGluZV9hY2Nlc3MiLCJzaWQiOiIxMWVhNGRhMy0xOGM5LTRlOTUtYTE0OS02NDg0ZGZiYTJhYWMiLCJlbWFpbF" +
            "92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImZpcnN0bmFtZWEgbGFzdG5hbWVhIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcmEiLCJna" +
            "XZlbl9uYW1lIjoiZmlyc3RuYW1lYSIsImZhbWlseV9uYW1lIjoibGFzdG5hbWVhIn0.kYiKXF7xYj5rJkfKJf5OgDn1t-2ZYxHMmecn" +
            "VLLSLWI7WPVVj18pmM5Cir-XwCy4RRSXmWQSwJ87hNIcoJFy1j2cm6Zu8NhWThSVTKp9UcGi2k1x0kDLKiRoJ92e2oSZL8TeKQpBGXc" +
            "eErICqiRxIvT4qnoQG_FEV2zGfQKfXFQSO9syBWbm9XRWFNJctZAs5n7hq-UQmK_mtQi-EbQsREPsdzNwgcYFm7ntaZjn2CuRxvtg_0" +
            "wNTZZNHDX9j4IRfCMihzchKW4PiYs28OTqAukIWmnQdCWgCkT7J7Tknzn77PMfGI5YcL6RJfpfH_0TRqhSjSRmdQWmnA58Z0yOTA"
        printAccessToken(atoken)
    }

    //
    // PRIVATE FUNCTIONS
    //
    private fun getAuthorizationServerMetadata(): OIDCProviderMetadata {
        val issuer = Issuer(issuerURI)
        val httpResponse = OIDCProviderConfigurationRequest(issuer).toHTTPRequest().send()
        assert(httpResponse.indicatesSuccess()) {
            "AS metadata request failed: ${httpResponse.statusCode} error code: ${httpResponse.statusMessage}"
        }
        val providerInfo = httpResponse.content
        val providerMetadata: OIDCProviderMetadata = OIDCProviderMetadata.parse(providerInfo)
        return providerMetadata
    }

    private fun getAuthorizationCodeUsingPAR() {
        println("getAuthorizationCodeUsingPAR")

        // get AS metadata
        val metadata: OIDCProviderMetadata = getAuthorizationServerMetadata().let {
            assert(it != null, { "metadata is null" })
            it!!
        }
        val authzEndpoint: URI = metadata.authorizationEndpointURI
        val parEndpoint: URI = metadata.pushedAuthorizationRequestEndpointURI

        // for production:
        // Create random state string for pairing the response to the request
        // val state = State()
        // Generate a new random 256 bit code verifier for PKCE
        // val codeVerifier = CodeVerifier()

        // Construct an OAuth 2.0 authorisation request as usual
        val authorizationRequest = AuthorizationRequest.Builder(ResponseType(ResponseType.Value.CODE), clientID)
            .scope(scope)
            .state(state)
            .redirectionURI(clientRedirectURI)
            .endpointURI(authzEndpoint)
            .codeChallenge(codeVerifier, CodeChallengeMethod.S256) // <--- PKCE
            .build()

        // Create the PAR request and POST it
        val httpRequest = PushedAuthorizationRequest(parEndpoint, authorizationRequest).toHTTPRequest()
        val httpResponse = httpRequest.send()

        // Process the PAR response
        val response = PushedAuthorizationResponse.parse(httpResponse)

        assert(response.indicatesSuccess()) {
            "PAR request failed, statusCode: ${response.toErrorResponse().errorObject.httpStatusCode}, " +
                "code: ${response.toErrorResponse().errorObject.code}, " +
                "description: ${response.toErrorResponse().errorObject.description}"
        }

        val successResponse = response.toSuccessResponse()
        println("Request URI: ${successResponse.requestURI}")
        println("Request URI expires in: ${successResponse.lifetime} seconds")

        // Construct the authZ request for the browser, with request_uri as
        // the sole parameter
        val authorizationRequestUri = AuthorizationRequest
            .Builder(successResponse.requestURI, clientID)
            .endpointURI(authzEndpoint)
            .build()
            .toURI()
        println("login using this link = $authorizationRequestUri")
    }

    private fun getAccessTokenByAuthorizationCode(authorizationCode: String) {
        println("getAccessTokenByAuthorizationCode")

        // get AS metadata
        val metadata: OIDCProviderMetadata = getAuthorizationServerMetadata().let {
            assert(it != null, { "metadata is null" })
            it!!
        }

        // debug
        val codeValue = authorizationCode

        val code = AuthorizationCode(codeValue)

        val tokenEndpoint = metadata.tokenEndpointURI

        val tokenRequest = TokenRequest(tokenEndpoint, clientID, AuthorizationCodeGrant(code, clientRedirectURI, codeVerifier))

        val httpTokenRequest = tokenRequest.toHTTPRequest()
        println("httpTokenRequest = $httpTokenRequest")
        println("httpTokenRequest.uri = ${httpTokenRequest.uri}")
        println("httpTokenRequest.method = ${httpTokenRequest.method}")
        println("httpTokenRequest.parameters = ${httpTokenRequest.queryParameters}")
        val httpTokenResponse = httpTokenRequest.send()

        assert(httpTokenResponse.indicatesSuccess()) {
            "TokenRequest failed, status code: ${httpTokenResponse.statusCode}, " +
                "status message: ${httpTokenResponse.statusMessage}, " +
                "content: ${httpTokenResponse.content}"
        }

        val tokenResponse = OIDCTokenResponse.parse(httpTokenResponse)
        println("tokenResponse.accessToken = ${tokenResponse.oidcTokens.accessToken}")
        println("tokenResponse.idToken = ${tokenResponse.oidcTokens.idTokenString}")

        val access_token = tokenResponse.oidcTokens.accessToken

        printAccessToken(access_token.value)
    }

    private fun printAccessToken(accessToken: String) {
        val jwt = SignedJWT.parse(accessToken)
        println("scopes: ${jwt.jwtClaimsSet.getStringClaim("scope")}")
        val jwtClaimsSet = jwt.jwtClaimsSet
        jwtClaimsSet.claims.forEach() { (k, v) ->
            println("  $k = $v")
        }
    }
}
