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

import com.nimbusds.jose.JWSAlgorithm
import java.time.Duration

/**
 * Properties for configuring DPoP.
 */
data class DPoPConfigurationProperties(
    val algorithms: Set<JWSAlgorithm>,
    val proofMaxAge: Duration,
    val cachePurgeInterval: Duration,
    val realm: String,
) {
    init {
        require(JWSAlgorithm.Family.SIGNATURE.containsAll(algorithms)) { "'algorithms' contains invalid values" }
        require(!proofMaxAge.isZero) { "'proofMaxAge' cannot be zero" }
        require(!cachePurgeInterval.isZero) { "'cachePurgeInterval' cannot be zero" }
        require(realm.isNotBlank()) { "'realm' cannot be blank" }
    }
}
