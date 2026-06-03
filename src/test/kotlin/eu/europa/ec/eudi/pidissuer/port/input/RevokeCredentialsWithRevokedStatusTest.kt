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

import arrow.core.left
import arrow.core.right
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import kotlinx.coroutines.test.runTest
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours

internal class RevokeCredentialsWithRevokedStatusTest {

    private val clock = Clock.System

    private fun credential(
        clientStatusUri: URI = URI.create("https://example.com/status"),
        clientStatusIndex: UInt = 0u,
        keyStorageUri: URI = URI.create("https://example.com/key-status"),
        keyStorageIndex: UInt = 0u,
    ) = IssuedCredential(
        format = Format("vc+sd-jwt"),
        type = "eu.europa.ec.eudi.pid.1",
        issuedAt = clock.now(),
        expiresAt = clock.now() + 24.hours,
        statusListToken = StatusListToken(
            statusList = URI.create("https://example.com/issuer-status"),
            index = 0u,
        ),
        clientStatusListToken = StatusListToken(
            statusList = clientStatusUri,
            index = clientStatusIndex,
        ),
        keyStorageStatusListToken = StatusListToken(
            statusList = keyStorageUri,
            index = keyStorageIndex,
        ),
    )

    @Test
    fun `no active credentials - nothing is revoked`() = runTest {
        val revoked = mutableListOf<IssuedCredential>()
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> },
            getActiveIssuedCredentials = { _ -> emptyList() },
            getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID.right() },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { revoked.add(it) },
        )

        useCase()

        assertTrue(revoked.isEmpty())
    }

    @Test
    fun `credential with all VALID statuses is not revoked`() = runTest {
        val credential = credential()
        val revoked = mutableListOf<IssuedCredential>()
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> },
            getActiveIssuedCredentials = { _ -> listOf(credential) },
            getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID.right() },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { revoked.add(it) },
        )

        useCase()

        assertTrue(revoked.isEmpty())
    }

    @Test
    fun `credential with INVALID client status is revoked`() = runTest {
        val credential = credential()
        val revoked = mutableListOf<IssuedCredential>()
        val clientStatusUri = URI.create("https://example.com/status")
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> },
            getActiveIssuedCredentials = { _ -> listOf(credential) },
            getStatusListTokenStatus = { uri, _ ->
                if (uri == clientStatusUri) StatusListTokenStatus.INVALID.right()
                else StatusListTokenStatus.VALID.right()
            },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { revoked.add(it) },
        )

        useCase()

        assertEquals(listOf(credential), revoked)
    }

    @Test
    fun `credential with INVALID key storage status is revoked`() = runTest {
        val keyStorageUri = URI.create("https://example.com/key-status")
        val credential = credential(keyStorageUri = keyStorageUri)
        val revoked = mutableListOf<IssuedCredential>()
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> },
            getActiveIssuedCredentials = { _ -> listOf(credential) },
            getStatusListTokenStatus = { uri, _ ->
                if (uri == keyStorageUri) StatusListTokenStatus.INVALID.right()
                else StatusListTokenStatus.VALID.right()
            },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { revoked.add(it) },
        )

        useCase()

        assertEquals(listOf(credential), revoked)
    }

    @Test
    fun `error revoking one credential does not prevent processing of remaining credentials`() = runTest {
        val credential1 = credential(clientStatusUri = URI.create("https://example.com/status/1"))
        val credential2 = credential(clientStatusUri = URI.create("https://example.com/status/2"))
        val revoked = mutableListOf<IssuedCredential>()
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> },
            getActiveIssuedCredentials = { _ -> listOf(credential1, credential2) },
            getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.INVALID.right() },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { credential ->
                if (credential == credential1) throw RuntimeException("Persistence error")
                revoked.add(credential)
            },
        )

        useCase()

        assertEquals(listOf(credential2), revoked)
    }

    @Test
    fun `credential is not revoked when status verification fails`() = runTest {
        val credential = credential()
        val revoked = mutableListOf<IssuedCredential>()
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> },
            getActiveIssuedCredentials = { _ -> listOf(credential) },
            getStatusListTokenStatus = { _, _ -> RuntimeException("Network error").left() },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { revoked.add(it) },
        )

        useCase()

        assertTrue(revoked.isEmpty())
    }

    @Test
    fun `expired credentials are deleted before checking revocation status`() = runTest {
        val expiredCredential = IssuedCredential(
            format = Format("vc+sd-jwt"),
            type = "eu.europa.ec.eudi.pid.1",
            issuedAt = clock.now() - 48.hours,
            expiresAt = clock.now() - 24.hours,
            statusListToken = null,
            clientStatusListToken = StatusListToken(
                statusList = URI.create("https://example.com/status"),
                index = 0u,
            ),
            keyStorageStatusListToken = StatusListToken(
                statusList = URI.create("https://example.com/key-status"),
                index = 0u,
            ),
        )
        val deleted = mutableListOf<IssuedCredential>()
        val useCase = RevokeCredentialsWithRevokedStatus(
            clock = clock,
            deleteExpiredIssuedCredentials = { _ -> deleted.add(expiredCredential) },
            getActiveIssuedCredentials = { _ -> emptyList() },
            getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID.right() },
            markStatusAsRevoked = { _, _ -> Unit.right() },
            deleteIssuedCredential = { },
        )

        useCase()

        assertEquals(listOf(expiredCredential), deleted)
    }
}
