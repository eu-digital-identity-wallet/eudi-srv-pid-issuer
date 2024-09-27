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
package eu.europa.ec.eudi.pidissuer.adapter.out.persistence

import eu.europa.ec.eudi.pidissuer.domain.IssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadIssuedCredentialsByNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(InMemoryIssuedCredentialRepository::class.java)

class InMemoryIssuedCredentialRepository(
    private val data: MutableList<IssuedCredentials> = mutableListOf(),
) {
    private val mutex = Mutex()

    val storeIssuedCredentials: StoreIssuedCredentials =
        StoreIssuedCredentials { credential ->
            mutex.withLock(this) {
                if (credential.notificationId != null) {
                    require(data.find { existing -> existing.notificationId == credential.notificationId } == null) {
                        "Notification Id '${credential.notificationId}' already in use"
                    }
                }
                data.add(credential)
                log.info("Stored $credential")
            }
        }

    val loadIssuedCredentialsByNotificationId: LoadIssuedCredentialsByNotificationId =
        LoadIssuedCredentialsByNotificationId { notificationId ->
            mutex.withLock(this) {
                data.find { credential -> credential.notificationId == notificationId }
            }
        }
}
