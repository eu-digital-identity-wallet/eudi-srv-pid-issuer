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
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetActiveIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.MarkStatusAsRevoked
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import org.slf4j.LoggerFactory
import java.net.URI

private val log = LoggerFactory.getLogger(RevokeCredentialsWithRevokedStatus::class.java)

/**
 * Use case that retrieves all active issued credentials and revokes any whose
 * client status or key storage status has been revoked in the respective status list.
 */
class RevokeCredentialsWithRevokedStatus(
    private val clock: Clock,
    private val deleteExpiredIssuedCredentials: DeleteExpiredIssuedCredentials,
    private val getActiveIssuedCredentials: GetActiveIssuedCredentials,
    private val getStatusListTokenStatus: GetStatusListTokenStatus,
    private val markStatusAsRevoked: MarkStatusAsRevoked,
    private val deleteIssuedCredential: DeleteIssuedCredential,
) {

    suspend operator fun invoke() {
        deleteExpiredIssuedCredentials(clock)
        val activeCredentials = getActiveIssuedCredentials(clock)
        log.info("Checking revocation status for {} active credential(s)", activeCredentials.size)

        activeCredentials
            .filter { it.statusListToken != null }
            .forEach { credential ->
                runCatching {
                    val clientStatusList = credential.clientStatusListToken.let {
                        it.statusList to it.index
                    }
                    val keyStorageStatusList = credential.keyStorageStatusListToken.let {
                        it.statusList to it.index
                    }
                    val shouldRevoke =
                        isStatusRevoked("client status", clientStatusList) ||
                            isStatusRevoked("key storage status", keyStorageStatusList)
                    if (shouldRevoke) {
                        log.info(
                            "Revoking credential with status list '{}' due to revoked client or key storage status",
                            credential.statusListToken,
                        )
                        markStatusAsRevoked(credential.statusListToken!!.statusList, credential.statusListToken.index)
                            .onRight {
                                deleteIssuedCredential(credential)
                            }
                            .onLeft { e ->
                                log.warn(
                                    "Failed to revoke credential with status list '{}' due to error: {}",
                                    credential.statusListToken,
                                    e.message,
                                    e,
                                )
                            }
                    }
                }.onFailure { e ->
                    log.error(
                        "Unexpected error processing credential: {}",
                        e.message,
                        e,
                    )
                }
            }
    }

    private suspend fun isStatusRevoked(
        statusName: String,
        statusListToken: Pair<URI, UInt>,
    ): Boolean {
        val (uri, index) = statusListToken
        return getStatusListTokenStatus(uri, index)
            .fold(
                ifLeft = { error ->
                    log.warn(
                        "Failed to check {} for credential with status list '{}': {}",
                        statusName,
                        statusListToken.first,
                        error.message,
                    )
                    false
                },
                ifRight = { statusToken -> statusToken == StatusListTokenStatus.INVALID },
            )
    }
}
