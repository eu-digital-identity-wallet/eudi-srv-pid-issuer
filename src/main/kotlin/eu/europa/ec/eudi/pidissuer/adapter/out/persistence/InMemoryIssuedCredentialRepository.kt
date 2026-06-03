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
package eu.europa.ec.eudi.pidissuer.adapter.out.persistence

import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetActiveIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadIssuedCredentialsByNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(InMemoryIssuedCredentialRepository::class.java)

class InMemoryIssuedCredentialRepository(
    private val data: MutableList<IssuedCredential> = mutableListOf(),
) {
    private val mutex = Mutex()

    val storeIssuedCredential: StoreIssuedCredential =
        StoreIssuedCredential { credential ->
            mutex.withLock(this) {
                data.add(credential)
                log.info(
                    "Stored credential of type '{}' with notificationId={}",
                    credential.type,
                    credential.notificationId,
                )
            }
        }

    val loadIssuedCredentialsByNotificationId: LoadIssuedCredentialsByNotificationId =
        LoadIssuedCredentialsByNotificationId { notificationId ->
            mutex.withLock(this) {
                data.filter { credential -> credential.notificationId == notificationId }
            }
        }

    val getActiveIssuedCredentials: GetActiveIssuedCredentials =
        GetActiveIssuedCredentials { clock ->
            mutex.withLock(this) {
                data.filter { credential -> credential.expiresAt > clock.now() && credential.statusListToken != null }
            }
        }

    val deleteExpiredIssuedCredentials: DeleteExpiredIssuedCredentials =
        DeleteExpiredIssuedCredentials { clock ->
            mutex.withLock(this) {
                val now = clock.now()
                val expired = data.filter { credential -> credential.expiresAt <= now }
                expired.forEach { credential ->
                    data.remove(credential)
                    log.info(
                        "Deleted expired credential of type '{}' with notificationId={}",
                        credential.type,
                        credential.notificationId,
                    )
                }
            }
        }

    val deleteIssuedCredential: DeleteIssuedCredential =
        DeleteIssuedCredential { credential ->
            mutex.withLock(this) {
                val removed = data.remove(credential)
                if (removed) {
                    log.info(
                        "Revoked credential of type '{}' with notificationId={}",
                        credential.type,
                        credential.notificationId,
                    )
                } else {
                    log.warn(
                        "Attempted to revoke credential of type '{}' with notificationId={} but it was not found",
                        credential.type,
                        credential.notificationId,
                    )
                }
            }
        }
}
