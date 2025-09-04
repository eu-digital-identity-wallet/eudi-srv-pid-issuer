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

import com.nimbusds.openid.connect.sdk.Nonce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Duration
import java.time.Instant

/**
 * A Nonce value used for DPoP authentication.
 */
data class DPoPNonce(val nonce: Nonce, val createdAt: Instant, val expiresAt: Instant)

/**
 * Checks if a value is a valid DPoP Nonce.
 */
fun interface ValidateDPoPNonce {
    suspend operator fun invoke(unvalidated: String): DPoPNonce?
}

/**
 * Generates a new Nonce value for DPoP, for a specific DPoP Access Token.
 */
fun interface GenerateDPoPNonce {
    suspend operator fun invoke(): DPoPNonce
}

/**
 * Cleans up any inactive DPoP Nonce values.
 */
fun interface CleanupInactiveDPoPNonce {
    suspend operator fun invoke()
}

/**
 * In memory repository providing implementations for [ValidateDPoPNonce], and [GenerateDPoPNonce].
 */
class InMemoryDPoPNonceRepository(
    private val clock: Clock,
    private val dpopNonceExpiresIn: Duration = Duration.ofMinutes(5L),
) {
    init {
        require(!dpopNonceExpiresIn.isZero && !dpopNonceExpiresIn.isNegative) { "dpopNonceExpiresIn must be positive" }
    }

    private val data = mutableSetOf<DPoPNonce>()
    private val mutex = Mutex()
    private val log = LoggerFactory.getLogger(InMemoryDPoPNonceRepository::class.java)

    val validateDPoPNonce: ValidateDPoPNonce by lazy {
        ValidateDPoPNonce { unvalidated ->
            mutex.withLock {
                data.find { dpopNonce -> dpopNonce.nonce.value == unvalidated }
            }
        }
    }

    val generateDPoPNonce: GenerateDPoPNonce by lazy {
        GenerateDPoPNonce {
            mutex.withLock {
                val createdAt = clock.instant()
                val expiresAt = createdAt + dpopNonceExpiresIn
                val dpopNonce = DPoPNonce(
                    nonce = Nonce(),
                    createdAt = createdAt,
                    expiresAt = expiresAt,
                )
                data.add(dpopNonce)
                dpopNonce
            }
        }
    }

    val cleanupInactiveDPoPNonce: CleanupInactiveDPoPNonce by lazy {
        CleanupInactiveDPoPNonce {
            mutex.withLock {
                val now = clock.instant()
                val inactive = data.filter { it.expiresAt >= now }
                inactive.forEach(data::remove)

                log.debug("Removed '${inactive.size}' inactive DPoPNonce values")
            }
        }
    }
}

/**
 * Policy for DPoP Nonce.
 */
sealed interface DPoPNoncePolicy {

    /**
     * [DPoPNonce] is enforced.
     */
    class Enforcing(
        val validateDPoPNonce: ValidateDPoPNonce,
        val generateDPoPNonce: GenerateDPoPNonce,
    ) : DPoPNoncePolicy

    /**
     * [DPoPNonce] is disabled.
     */
    data object Disabled : DPoPNoncePolicy
}
