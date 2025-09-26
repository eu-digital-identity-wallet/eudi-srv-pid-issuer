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
package eu.europa.ec.eudi.pidissuer.domain

import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.toJavaZoneId
import kotlinx.datetime.toKotlinTimeZone
import kotlinx.datetime.toLocalDateTime
import java.time.ZonedDateTime
import java.util.Date
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant

interface Clock {
    fun now(): Instant
    fun timeZone(): TimeZone

    fun Instant.toLocalDateTime(): LocalDateTime = toLocalDateTime(timeZone())
    fun Instant.toLocalDate(): LocalDate = toLocalDateTime().date
    fun Instant.toZonedDateTime(): ZonedDateTime = ZonedDateTime.ofInstant(toJavaInstant(), timeZone().toJavaZoneId())
    fun LocalDate.atStartOfDay(): Instant = atStartOfDayIn(timeZone())

    companion object {
        val System: Clock = object : Clock {
            override fun now(): Instant = kotlin.time.Clock.System.now()
            override fun timeZone(): TimeZone = TimeZone.currentSystemDefault()
        }

        fun fixed(now: Instant, timeZone: TimeZone): Clock = object : Clock {
            override fun now(): Instant = now
            override fun timeZone(): TimeZone = timeZone
        }

        fun fixed(now: ZonedDateTime): Clock = fixed(now.toInstant().toKotlinInstant(), now.zone.toKotlinTimeZone())
    }
}

fun Date.toKotlinInstant(): Instant = toInstant().toKotlinInstant()
fun Instant.toJavaDate(): Date = Date.from(toJavaInstant())
