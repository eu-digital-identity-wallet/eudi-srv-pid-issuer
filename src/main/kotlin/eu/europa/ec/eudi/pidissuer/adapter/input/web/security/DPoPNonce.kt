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

import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import com.nimbusds.openid.connect.sdk.Nonce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Clock
import java.time.Duration
import java.time.Instant

/**
 * A Nonce value used for DPoP authentication.
 */
data class DPoPNonce(val nonce: Nonce, val jwkThumbprint: JWKThumbprintConfirmation, val createdAt: Instant, val expiresAt: Instant)

/**
 * Loads the active Nonce value for DPoP, for a specific JWK Thumbprint.
 */
fun interface LoadActiveDPoPNonce {
    suspend operator fun invoke(jwkThumbprint: JWKThumbprintConfirmation): DPoPNonce?
}

/**
 * Generates a new Nonce value for DPoP, for a specific JWK Thumbprint.
 */
fun interface GenerateDPoPNonce {
    suspend operator fun invoke(jwkThumbprint: JWKThumbprintConfirmation): DPoPNonce
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

    private val data = mutableMapOf<JWKThumbprintConfirmation, DPoPNonce>()
    private val mutex = Mutex()

    val loadActiveDPoPNonceByClient: LoadActiveDPoPNonce by lazy {
        LoadActiveDPoPNonce { jwkThumbprint ->
            mutex.withLock {
                data[jwkThumbprint]?.takeIf { dpopNonce -> dpopNonce.expiresAt > clock.instant() }
            }
        }
    }

    val generateDPoPNonce: GenerateDPoPNonce by lazy {
        GenerateDPoPNonce { jwkThumbprint ->
            mutex.withLock {
                val createdAt = clock.instant()
                val expiresAt = createdAt + dpopNonceExpiresIn
                val dpopNonce = DPoPNonce(
                    nonce = Nonce(),
                    jwkThumbprint = jwkThumbprint,
                    createdAt = createdAt,
                    expiresAt = expiresAt,
                )
                data[jwkThumbprint] = dpopNonce
                dpopNonce
            }
        }
    }
}
