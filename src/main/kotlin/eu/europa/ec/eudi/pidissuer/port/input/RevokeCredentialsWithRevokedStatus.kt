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

import arrow.core.raise.effect
import arrow.core.raise.fold
import arrow.fx.coroutines.parMap
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetNonExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.MarkStatusAsRevoked
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import kotlin.time.Clock

private val log = LoggerFactory.getLogger(RevokeCredentialsWithRevokedStatus::class.java)

/**
 * Use case that retrieves all active issued credentials and revokes any whose
 * client status or key storage status has been revoked in the respective status list.
 */
class RevokeCredentialsWithRevokedStatus(
    private val clock: Clock,
    private val deleteExpiredIssuedCredentials: DeleteExpiredIssuedCredentials,
    private val getNonExpiredIssuedCredentials: GetNonExpiredIssuedCredentials,
    private val getStatusListTokenStatus: GetStatusListTokenStatus,
    private val markStatusAsRevoked: MarkStatusAsRevoked,
    private val deleteIssuedCredential: DeleteIssuedCredential,
    private val concurrency: Int = 2,
) {
    private val dispatcher = Dispatchers.IO

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend operator fun invoke() {
        log.info("Deleting expired issued credentials")
        deleteExpiredIssuedCredentials(clock.now())

        log.info("Checking revocation status for active credential(s)")
        val activeCredentials = getNonExpiredIssuedCredentials(clock.now())

        activeCredentials.parMap(dispatcher, concurrency) { credential ->
            processCredential(credential)
        }
    }

    private suspend fun processCredential(credential: IssuedCredential): Unit =
        coroutineScope {
            val clientStatus =
                async {
                    isStatusRevoked("client status", credential.clientStatus)
                }
            val keyStorageStatus =
                async {
                    credential.keyStorageStatus != null &&
                        isStatusRevoked(
                            "key storage status",
                            credential.keyStorageStatus,
                        )
                }
            val mustRevoke = clientStatus.await() || keyStorageStatus.await()
            if (mustRevoke) {
                revokeCredential(credential)
            }
        }

    private suspend fun revokeCredential(credential: IssuedCredential) {
        effect {
            if (credential.status != null) {
                markStatusAsRevoked(credential.status)
            }
            deleteIssuedCredential(credential)
        }.fold(
            transform = {},
            recover = { e -> log(credential.status, e) },
            catch = { t ->
                log.warn(
                    "Failed to revoke credential with status list '{}'",
                    credential.status?.statusList,
                    t,
                )
            },
        )
    }

    private suspend fun isStatusRevoked(
        statusName: String,
        statusListToken: StatusListToken,
    ): Boolean =
        effect {
            val (uri, index) = statusListToken
            val statusToken = getStatusListTokenStatus(uri, index)
            statusToken == StatusListTokenStatus.INVALID
        }.fold(
            transform = { it },
            recover = { e ->
                log(statusName, statusListToken, e)
                false
            },
        )

    private fun log(
        status: StatusListToken?,
        error: MarkStatusAsRevoked.Error,
    ) {
        log.warn(
            "Failed to revoke credential with status list '{}' due to error: {}",
            status?.statusList,
            error.value,
        )
    }

    private fun log(
        statusName: String,
        statusListToken: StatusListToken,
        error: GetStatusListTokenStatus.Error,
    ) {
        log.warn(
            "Failed to check {} for credential with status list '{}",
            statusName,
            statusListToken.statusList,
            error.value,
        )
    }
}
