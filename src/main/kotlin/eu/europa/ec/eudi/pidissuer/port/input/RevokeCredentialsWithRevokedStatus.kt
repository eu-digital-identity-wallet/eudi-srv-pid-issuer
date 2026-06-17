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

import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetNonExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.MarkStatusAsRevoked
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flatMapMerge
import kotlinx.coroutines.flow.flow
import org.slf4j.LoggerFactory

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
) {
    @OptIn(ExperimentalCoroutinesApi::class)
    suspend operator fun invoke() {
        log.info("Deleting expired issued credentials")
        deleteExpiredIssuedCredentials(clock.now())

        log.info("Checking revocation status for active credential(s)")
        val activeCredentials = getNonExpiredIssuedCredentials(clock.now())

        activeCredentials
            .flatMapMerge { credential ->
                flow {
                    emit(processCredential(credential))
                }
            }.collect { }
    }

    private suspend fun processCredential(credential: IssuedCredential) =
        runCatching {
            val mustRevoke =
                isStatusRevoked(
                    "client status",
                    credential.clientStatus,
                ) || (
                    credential.keyStorageStatus != null &&
                        isStatusRevoked(
                            "key storage status",
                            credential.keyStorageStatus,
                        )
                )
            if (mustRevoke) {
                revokeCredential(credential)
            }
        }.onFailure { e ->
            log.error(
                "Unexpected error processing credential: {}",
                e.message,
                e,
            )
        }

    private suspend fun revokeCredential(credential: IssuedCredential) {
        if (credential.status != null) {
            markStatusAsRevoked(credential.status)
                .onRight {
                    deleteIssuedCredential(credential)
                }.onLeft { e ->
                    log.warn(
                        "Failed to revoke credential with status list '{}' due to error: {}",
                        credential.status.statusList,
                        e.message,
                        e,
                    )
                }
        } else {
            deleteIssuedCredential(credential)
        }
    }

    private suspend fun isStatusRevoked(
        statusName: String,
        statusListToken: StatusListToken,
    ): Boolean {
        val (uri, index) = statusListToken
        return getStatusListTokenStatus(uri, index).fold(
            ifLeft = { error ->
                log.warn(
                    "Failed to check {} for credential with status list '{}': {}",
                    statusName,
                    statusListToken.statusList,
                    error.message,
                )
                false
            },
            ifRight = { statusToken -> statusToken == StatusListTokenStatus.INVALID },
        )
    }
}
