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
package eu.europa.ec.eudi.pidissuer.adapter.out.util

import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.time.TimeSource

fun randomInstantInThePast(
    clock: Clock = Clock.System,
    random: Random = Random,
): Instant {
    val now =
        TimeSource.Monotonic
            .markNow()
            .elapsedNow()
            .let { clock.now() - it }
    val randomDuration = (random.nextDouble(0.0, now.epochSeconds.toDouble())).seconds
    return Instant.fromEpochSeconds(
        randomDuration.inWholeSeconds,
        nanosecondAdjustment = randomDuration.inWholeNanoseconds % 1_000_000_000,
    )
}
