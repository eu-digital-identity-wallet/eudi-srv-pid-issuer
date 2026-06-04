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

import eu.europa.ec.eudi.pidissuer.domain.Format
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.domain.NotificationId
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import java.net.URI
import java.time.OffsetDateTime
import java.time.ZoneOffset
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant

@Table("issued_credential")
data class IssuedCredentialEntity(
    @Id
    @Column("id")
    val id: Long? = null,
    @Column("credential_format")
    val format: String,
    @Column("credential_type")
    val type: String,
    @Column("issued_at")
    val issuedAt: OffsetDateTime,
    @Column("expires_at")
    val expiresAt: OffsetDateTime,
    @Column("notification_id")
    val notificationId: String?,
    @Column("status_list_uri")
    val statusListUri: String?,
    @Column("status_list_index")
    val statusListIndex: Long?,
    @Column("client_status_list_uri")
    val clientStatusListUri: String,
    @Column("client_status_list_index")
    val clientStatusListIndex: Long,
    @Column("key_storage_status_list_uri")
    val keyStorageStatusListUri: String,
    @Column("key_storage_status_list_index")
    val keyStorageStatusListIndex: Long,
) {
    fun toDomain(): IssuedCredential =
        IssuedCredential(
            format = Format(format),
            type = type,
            issuedAt = issuedAt.toInstant().toKotlinInstant(),
            expiresAt = expiresAt.toInstant().toKotlinInstant(),
            notificationId = notificationId?.let { NotificationId(it) },
            statusListToken = if (statusListUri != null && statusListIndex != null) {
                StatusListToken(
                    statusList = URI.create(statusListUri),
                    index = statusListIndex.toUInt(),
                )
            } else {
                null
            },
            clientStatusListToken = StatusListToken(
                statusList = URI.create(clientStatusListUri),
                index = clientStatusListIndex.toUInt(),
            ),
            keyStorageStatusListToken = StatusListToken(
                statusList = URI.create(keyStorageStatusListUri),
                index = keyStorageStatusListIndex.toUInt(),
            ),
            persistenceId = id,
        )

    companion object {
        fun fromDomain(credential: IssuedCredential): IssuedCredentialEntity =
            IssuedCredentialEntity(
                format = credential.format.value,
                type = credential.type,
                issuedAt = credential.issuedAt.toOffsetDateTime(),
                expiresAt = credential.expiresAt.toOffsetDateTime(),
                notificationId = credential.notificationId?.value,
                statusListUri = credential.statusListToken?.statusList?.toString(),
                statusListIndex = credential.statusListToken?.index?.toLong(),
                clientStatusListUri = credential.clientStatusListToken.statusList.toString(),
                clientStatusListIndex = credential.clientStatusListToken.index.toLong(),
                keyStorageStatusListUri = credential.keyStorageStatusListToken.statusList.toString(),
                keyStorageStatusListIndex = credential.keyStorageStatusListToken.index.toLong(),
            )
    }
}

internal fun Instant.toOffsetDateTime(): OffsetDateTime =
    OffsetDateTime.ofInstant(toJavaInstant(), ZoneOffset.UTC)
