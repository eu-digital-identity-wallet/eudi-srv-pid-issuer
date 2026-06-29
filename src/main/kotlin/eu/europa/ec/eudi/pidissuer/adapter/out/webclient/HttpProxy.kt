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
package eu.europa.ec.eudi.pidissuer.adapter.out.webclient

import io.ktor.http.*

sealed interface HttpProxyOption {
    data object None : HttpProxyOption

    data class Using(
        val proxy: HttpProxy,
    ) : HttpProxyOption

    fun proxy(): HttpProxy? =
        when (this) {
            None -> null
            is Using -> proxy
        }
}

data class HttpProxy(
    val url: Url,
    val username: String? = null,
    val password: String? = null,
) {
    init {
        require(password == null || username != null) {
            "Password cannot be set if username is null"
        }
        require(url.protocol == URLProtocol.HTTP) {
            "Url should be Http"
        }
        require(url.encodedPathAndQuery.isBlank()) {
            "No path or query params should be present in the Url"
        }
        require(url.fragment.isEmpty()) {
            "No fragment should be present in the Url"
        }
    }
}
