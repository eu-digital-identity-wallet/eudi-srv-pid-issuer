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

import arrow.core.NonEmptySet
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm
import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 * Properties for configuring DPoP.
 */
@ConfigurationProperties("spring.security.oauth2.resourceserver.dpop")
data class DPoPConfigurationProperties(
    val algorithms: Set<String>,
    val proofMaxAge: Duration,
    val cachePurgeInterval: Duration,
    val realm: String,
) {
    init {
        require(algorithms.isNotEmpty()) { "'spring.security.oauth2.resourceserver.dpop.algorithms' is required" }
        require(JWSAlgorithm.Family.SIGNATURE.map { it.name }.containsAll(algorithms)) {
            "'spring.security.oauth2.resourceserver.dpop.algorithms' contains invalid values"
        }
        require(!proofMaxAge.isZero) {
            "'spring.security.oauth2.resourceserver.dpop.proof-max-age' cannot be zero"
        }
        require(!cachePurgeInterval.isZero) {
            "'spring.security.oauth2.resourceserver.dpop.cache-purge-interval' cannot be zero"
        }
        require(realm.isNotBlank()) {
            "'spring.security.oauth2.resourceserver.dpop.realm' cannot be blank"
        }
    }

    /**
     * Gets the supported [algorithms][JWSAlgorithm].
     */
    fun jwsAlgorithms(): NonEmptySet<JWSAlgorithm> =
        algorithms.map { JWSAlgorithm.parse(it) }.toNonEmptySetOrNull()!!
}
