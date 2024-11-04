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

import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
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
data class DPoPNonce(val nonce: Nonce, val accessToken: DPoPAccessToken, val createdAt: Instant, val expiresAt: Instant)

/**
 * Loads the active Nonce value for DPoP, for a specific DPoP Access Token.
 */
fun interface LoadActiveDPoPNonce {
    suspend operator fun invoke(accessToken: DPoPAccessToken): DPoPNonce?
}

/**
 * Generates a new Nonce value for DPoP, for a specific DPoP Access Token.
 */
fun interface GenerateDPoPNonce {
    suspend operator fun invoke(accessToken: DPoPAccessToken): DPoPNonce
}

/**
 * Cleans up any inactive DPoP Nonce values.
 */
fun interface CleanupInactiveDPoPNonce {
    suspend operator fun invoke()
}

/**
 * In memory repository providing implementations for [LoadActiveDPoPNonce], and [GenerateDPoPNonce].
 */
class InMemoryDPoPNonceRepository(
    private val clock: Clock,
    private val dpopNonceExpiresIn: Duration = Duration.ofMinutes(5L),
) {
    init {
        require(!dpopNonceExpiresIn.isZero && !dpopNonceExpiresIn.isNegative) { "dpopNonceExpiresIn must be positive" }
    }

    private val data = mutableMapOf<DPoPAccessToken, DPoPNonce>()
    private val mutex = Mutex()
    private val log = LoggerFactory.getLogger(InMemoryDPoPNonceRepository::class.java)

    val loadActiveDPoPNonce: LoadActiveDPoPNonce by lazy {
        LoadActiveDPoPNonce { accessToken ->
            mutex.withLock {
                data[accessToken]?.takeIf { dpopNonce -> dpopNonce.expiresAt > clock.instant() }
            }
        }
    }

    val generateDPoPNonce: GenerateDPoPNonce by lazy {
        GenerateDPoPNonce { accessToken ->
            mutex.withLock {
                val createdAt = clock.instant()
                val expiresAt = createdAt + dpopNonceExpiresIn
                val dpopNonce = DPoPNonce(
                    nonce = Nonce(),
                    accessToken = accessToken,
                    createdAt = createdAt,
                    expiresAt = expiresAt,
                )
                data[accessToken] = dpopNonce
                dpopNonce
            }
        }
    }

    val cleanupInactiveDPoPNonce: CleanupInactiveDPoPNonce by lazy {
        CleanupInactiveDPoPNonce {
            mutex.withLock {
                val now = clock.instant()
                val inactive = data.entries.filter { (_, dpopNonce) -> dpopNonce.expiresAt >= now }.map { it.key }
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
     * Gets the [DPoPNonce] associated with [accessToken].
     * In case no [DPoPNonce] is associated with [accessToken] a new one might be generated.
     */
    suspend fun getActiveOrGenerateNew(accessToken: DPoPAccessToken): DPoPNonce?

    /**
     * [DPoPNonce] is enforced.
     */
    class Enforcing(
        val loadActiveDPoPNonce: LoadActiveDPoPNonce,
        val generateDPoPNonce: GenerateDPoPNonce,
    ) : DPoPNoncePolicy {
        override suspend fun getActiveOrGenerateNew(accessToken: DPoPAccessToken): DPoPNonce =
            loadActiveDPoPNonce(accessToken) ?: generateDPoPNonce(accessToken)
    }

    /**
     * [DPoPNonce] is disabled.
     */
    data object Disabled : DPoPNoncePolicy {
        override suspend fun getActiveOrGenerateNew(accessToken: DPoPAccessToken): DPoPNonce? = null
    }
}
