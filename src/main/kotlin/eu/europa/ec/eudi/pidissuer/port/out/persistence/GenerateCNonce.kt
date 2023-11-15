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
package eu.europa.ec.eudi.pidissuer.port.out.persistence

import eu.europa.ec.eudi.pidissuer.domain.CNonce
import java.time.Clock
import java.time.Duration
import java.util.*

/**
 * Generates a new [CNonce].
 */
fun interface GenerateCNonce {
    suspend operator fun invoke(accessToken: String, clock: Clock): CNonce

    companion object {
        fun random(duration: Duration): GenerateCNonce = GenerateCNonce { accessToken, clock ->
            CNonce(accessToken, UUID.randomUUID().toString(), clock.instant(), duration)
        }
    }
}
