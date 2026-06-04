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

import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetActiveIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadIssuedCredentialsByNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import org.slf4j.LoggerFactory
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.data.repository.kotlin.CoroutineSortingRepository
import java.time.OffsetDateTime

private val log = LoggerFactory.getLogger(PostgresIssuedCredentialRepository::class.java)

/**
 * Spring Data R2DBC repository for [IssuedCredentialEntity].
 */
interface IssuedCredentialR2dbcRepository :
    CoroutineCrudRepository<IssuedCredentialEntity, Long>,
    CoroutineSortingRepository<IssuedCredentialEntity, Long> {

    suspend fun findAllByNotificationId(notificationId: String): List<IssuedCredentialEntity>

    @Query(
        """
        SELECT * FROM issued_credential
        WHERE expires_at > :now
          AND status_list_uri IS NOT NULL
          AND status_list_index IS NOT NULL
        """,
    )
    fun findAllActive(now: OffsetDateTime): Flow<IssuedCredentialEntity>

    @Query("DELETE FROM issued_credential WHERE expires_at <= :now")
    suspend fun deleteAllExpiredBefore(now: OffsetDateTime): Int?

    @Query(
        """
        DELETE FROM issued_credential
        WHERE notification_id IS NOT DISTINCT FROM :notificationId
          AND format = :format
          AND type = :type
          AND issued_at = :issuedAt
          AND expires_at = :expiresAt
        """,
    )
    suspend fun deleteByFields(
        notificationId: String?,
        format: String,
        type: String,
        issuedAt: OffsetDateTime,
        expiresAt: OffsetDateTime,
    ): Int?
}

/**
 * PostgreSQL-backed adapter implementing all issued-credential persistence ports.
 */
class PostgresIssuedCredentialRepository(
    private val r2dbc: IssuedCredentialR2dbcRepository,
) {
    val storeIssuedCredential: StoreIssuedCredential =
        StoreIssuedCredential { r2dbc.save(IssuedCredentialEntity.fromDomain(it)) }

    val loadIssuedCredentialsByNotificationId: LoadIssuedCredentialsByNotificationId =
        LoadIssuedCredentialsByNotificationId { notificationId ->
            r2dbc.findAllByNotificationId(notificationId.value)
                .map { it.toDomain() }
        }

    val getActiveIssuedCredentials: GetActiveIssuedCredentials =
        GetActiveIssuedCredentials { clock ->
            val now = clock.now().toOffsetDateTime()
            r2dbc.findAllActive(now)
                .map { it.toDomain() }
                .toList()
        }

    val deleteExpiredIssuedCredentials: DeleteExpiredIssuedCredentials =
        DeleteExpiredIssuedCredentials { clock ->
            val now = clock.now().toOffsetDateTime()
            val deleted = r2dbc.deleteAllExpiredBefore(now) ?: 0
            if (deleted > 0) {
                log.info("Deleted {} expired issued credential(s)", deleted)
            }
        }

    val deleteIssuedCredential: DeleteIssuedCredential =
        DeleteIssuedCredential { credential ->
            val deleted = if (credential.persistenceId != null) {
                r2dbc.deleteById(credential.persistenceId)
                1
            } else {
                r2dbc.deleteByFields(
                    notificationId = credential.notificationId?.value,
                    format = credential.format.value,
                    type = credential.type,
                    issuedAt = credential.issuedAt.toOffsetDateTime(),
                    expiresAt = credential.expiresAt.toOffsetDateTime(),
                ) ?: 0
            }
            if (deleted > 0) {
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
