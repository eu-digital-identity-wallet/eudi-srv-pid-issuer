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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.effect
import arrow.core.raise.fold
import eu.europa.ec.eudi.pidissuer.domain.NotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadIssuedCredentialsByNotificationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(HandleNotificationRequest::class.java)

/**
 * Handles an incoming Notification Request.
 */
class HandleNotificationRequest(
    private val loadIssuedCredentialsByNotificationId: LoadIssuedCredentialsByNotificationId,
) {
    suspend operator fun invoke(requestBody: JsonElement): NotificationResponse =
        effect {
            process(requestBody)
        }.fold(
            transform = { NotificationResponse.Success },
            recover = { NotificationResponse.NotificationErrorResponseTO(it) },
        )

    context(_: Raise<ErrorTypeTO>)
    suspend fun process(requestBody: JsonElement) {
        val notificationRequest = parseRequest(requestBody)
        val notificationId = NotificationId(notificationRequest.notificationId)
        val credentials = loadIssuedCredentialsByNotificationId(notificationId)
        ensureNotNull(credentials) { ErrorTypeTO.InvalidNotificationId }
        log.info("Received Notification Request '$notificationRequest' for Credentials '$credentials'")
    }

    context(_: Raise<ErrorTypeTO>)
    private fun parseRequest(requestBody: JsonElement): NotificationRequestTO =
        catch({ Json.decodeFromJsonElement(NotificationRequestTO.serializer(), requestBody) }) {
            raise(ErrorTypeTO.InvalidNotificationRequest)
        }
}
