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
package eu.europa.ec.eudi.pidissuer.domain

import kotlinx.datetime.TimeZone
import kotlinx.datetime.toJavaZoneId
import java.time.ZonedDateTime
import java.util.*
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant

fun Date.toKotlinInstant(): Instant = toInstant().toKotlinInstant()

fun Instant.toJavaDate(): Date = Date.from(toJavaInstant())

fun Instant.toZonedDateTime(timeZone: TimeZone): ZonedDateTime = ZonedDateTime.ofInstant(toJavaInstant(), timeZone.toJavaZoneId())
