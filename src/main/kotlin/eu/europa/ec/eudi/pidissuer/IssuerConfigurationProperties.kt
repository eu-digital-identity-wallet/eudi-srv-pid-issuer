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
package eu.europa.ec.eudi.pidissuer

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import java.net.URI
import java.net.URL
import java.time.Duration as JavaDuration

internal enum class AccessTokenType {
    DPoP,
    Bearer,
    BearerAndDPoPIfAvailable,
}

data class KeycloakConfigurationProperties(
    val serverUrl: URL,
    val authenticationRealm: String,
    val clientId: String,
    val username: String,
    val password: String,
    val userRealm: String,
) {
    init {
        require(authenticationRealm.isNotBlank()) { "'authenticationRealm' cannot be blank" }
        require(clientId.isNotBlank()) { "'clientId' cannot be blank" }
        require(username.isNotBlank()) { "'username' cannot be blank" }
        require(password.isNotBlank()) { "'password' cannot be blank" }
        require(userRealm.isNotBlank()) { "'userRealm' cannot be blank" }
    }
}

@ConfigurationProperties("issuer.metadata")
internal data class IssuerMetadataProperties(
    val preferredClientStatusPeriod: JavaDuration,
    val display: List<DisplayProperties> = emptyList(),
) {
    data class DisplayProperties(
        val name: String? = null,
        val locale: String? = null,
        val logo: LogoProperties? = null,
    )

    data class LogoProperties(
        val uri: URI,
        val alternativeText: String? = null,
    )
}

@ConfigurationProperties("issuer.sd-jwt-vc")
internal data class SdJwtVcProperties(
    val typeMetadata: List<TypeMetadataProperties>,
) {
    init {
        val vcts = typeMetadata.map { it.vct }
        require(vcts.size == vcts.distinct().size)
    }

    data class TypeMetadataProperties(
        val vct: String,
        val resource: Resource,
    ) {
        init {
            require(vct.isNotBlank()) { "'vct' cannot be blank" }
            require(resource.exists()) { "'resource' must exist" }
        }
    }
}

internal enum class KeyOption {
    GenerateRandom,
    LoadFromKeystore,
}
