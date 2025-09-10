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

import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

/**
 * Error returned in case of DPoP authentication failures.
 */
sealed class DPoPTokenError(
    errorCode: String,
    description: String,
    val status: HttpStatus,
) : OAuth2Error(errorCode, description, null) {

    /**
     * Indicates an invalid request.
     */
    class InvalidRequest(description: String) : DPoPTokenError(OAuth2ErrorCodes.INVALID_REQUEST, description, HttpStatus.BAD_REQUEST)

    /**
     * Indicates an invalid access token.
     */
    class InvalidToken(description: String) : DPoPTokenError(OAuth2ErrorCodes.INVALID_TOKEN, description, HttpStatus.UNAUTHORIZED)

    /**
     * Indicates an internal server error.
     */
    class ServerError(
        description: String,
        val error: Throwable,
    ) : DPoPTokenError(OAuth2ErrorCodes.SERVER_ERROR, description, HttpStatus.INTERNAL_SERVER_ERROR)

    /**
     * Indicates DPoP Nonce must be used.
     */
    class UseDPoPNonce(description: String) : DPoPTokenError("use_dpop_nonce", description, HttpStatus.UNAUTHORIZED)

    companion object {

        /**
         * Creates a new 'invalid request' error.
         */
        fun invalidRequest(description: String): InvalidRequest = InvalidRequest(description)

        /**
         * Creates a new 'invalid token' error.
         */
        fun invalidToken(description: String): InvalidToken = InvalidToken(description)

        /**
         * Creates a new 'server error' error.
         */
        fun serverError(description: String, error: Throwable): ServerError = ServerError(description, error)

        /**
         * Creates a new 'use dpop nonce' error.
         */
        fun useDPoPNonce(description: String): UseDPoPNonce = UseDPoPNonce(description)
    }
}
