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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.Either
import eu.europa.ec.eudi.pidissuer.domain.NotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadIssuedCredentialsByNotificationId
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import org.slf4j.LoggerFactory

@Suppress("unused")
@Serializable
enum class EventTypeTO {
    /**
     * The Credential was successfully stored in the Wallet, with or without user action.
     */
    @SerialName("credential_accepted")
    CredentialAccepted,

    /**
     * Unsuccessful Credential issuance was caused by a user action.
     */
    @SerialName("credential_deleted")
    CredentialDeleted,

    /**
     * Unsuccessful Credential issuance (all other cases).
     */
    @SerialName("credential_failure")
    CredentialFailure,
}

@Serializable
data class NotificationRequestTO(
    @SerialName("notification_id") @Required val notificationId: String,
    @SerialName("event") @Required val eventType: EventTypeTO,
    @SerialName("event_description") val description: String? = null,
)

@Serializable
enum class ErrorTypeTO {
    /**
     * The notification_id in the Notification Request was invalid.
     */
    @SerialName("invalid_notification_id")
    InvalidNotificationId,

    /**
     *  The Notification Request is missing a required parameter, includes
     *  an unsupported parameter or parameter value, repeats the same parameter,
     *  or is otherwise malformed.
     */
    @SerialName("invalid_notification_request")
    InvalidNotificationRequest,
}

sealed interface NotificationResponse {

    /**
     * Indicate a Notification Request was successfully handled.
     */
    data object Success : NotificationResponse

    /**
     * Indicates a NotificationRequest could not be successfully handled.
     */
    @Serializable
    data class NotificationErrorResponseTO(
        @SerialName("error") @Required val errorType: ErrorTypeTO,
    ) : NotificationResponse
}

private val log = LoggerFactory.getLogger(HandleNotificationRequest::class.java)

/**
 * Handles an incoming Notification Request.
 */
class HandleNotificationRequest(
    private val loadIssuedCredentialsByNotificationId: LoadIssuedCredentialsByNotificationId,
) {
    suspend operator fun invoke(requestBody: JsonElement): NotificationResponse =
        Either.catch { Json.decodeFromJsonElement<NotificationRequestTO>(requestBody) }
            .fold(
                ifLeft = { NotificationResponse.NotificationErrorResponseTO(ErrorTypeTO.InvalidNotificationRequest) },
                ifRight = { notificationRequest ->
                    val notificationId = NotificationId(notificationRequest.notificationId)
                    val credentials = loadIssuedCredentialsByNotificationId(notificationId)

                    credentials?.let {
                        log.info("Received Notification Request '$notificationRequest' for Credentials '$it'")
                        NotificationResponse.Success
                    } ?: NotificationResponse.NotificationErrorResponseTO(ErrorTypeTO.InvalidNotificationId)
                },
            )
}
