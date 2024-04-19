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
package eu.europa.ec.eudi.pidissuer.security

import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

/**
 * Error returned in case of DPoP authentication failures.
 */
class DPoPTokenError private constructor(
    errorCode: String,
    description: String,
    val status: HttpStatus,
) : OAuth2Error(errorCode, description, null) {

    companion object {

        /**
         * Creates a new 'invalid request' error.
         */
        fun invalidRequest(description: String): DPoPTokenError =
            DPoPTokenError(OAuth2ErrorCodes.INVALID_REQUEST, description, HttpStatus.BAD_REQUEST)

        /**
         * Creates a new 'invalid token' error.
         */
        fun invalidToken(description: String): DPoPTokenError =
            DPoPTokenError(OAuth2ErrorCodes.INVALID_TOKEN, description, HttpStatus.UNAUTHORIZED)

        /**
         * Creates a new 'server error' error.
         */
        fun serverError(description: String): DPoPTokenError =
            DPoPTokenError(OAuth2ErrorCodes.SERVER_ERROR, description, HttpStatus.INTERNAL_SERVER_ERROR)
    }
}
