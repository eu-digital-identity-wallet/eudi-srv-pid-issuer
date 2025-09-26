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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateNonce
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyNonce
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Properties for configuring DPoP.
 */
data class DPoPConfigurationProperties(
    val algorithms: Set<JWSAlgorithm>,
    val proofMaxAge: Duration,
    val cachePurgeInterval: Duration,
    val realm: String?,
) {
    init {
        require(JWSAlgorithm.Family.SIGNATURE.containsAll(algorithms)) { "'algorithms' contains invalid values" }
        require(proofMaxAge.isPositive()) { "'proofMaxAge' must be positive" }
        require(cachePurgeInterval.isPositive()) { "'cachePurgeInterval' must be positive" }
    }
}

/**
 * Policy for DPoP Nonce.
 */
sealed interface DPoPNoncePolicy {

    /**
     * DPoP Nonce is enforced.
     */
    class Enforcing(
        val verifyDPoPNonce: VerifyNonce,
        private val generateDPoPNonce: GenerateNonce,
        private val dpopNonceExpiresIn: Duration,
    ) : DPoPNoncePolicy {
        suspend fun generateDPoPNonce(generatedAt: Instant): String = generateDPoPNonce(generatedAt, dpopNonceExpiresIn)
    }

    /**
     * DPoP Nonce is disabled.
     */
    data object Disabled : DPoPNoncePolicy
}
