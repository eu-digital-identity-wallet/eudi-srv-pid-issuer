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

import arrow.core.raise.context.raise
import arrow.core.right
import eu.europa.ec.eudi.pidissuer.domain.Format
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock
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
        status =
            StatusListToken(
                statusList = URI.create("https://example.com/issuer-status"),
                index = 0u,
            ),
        clientStatus =
            StatusListToken(
                statusList = clientStatusUri,
                index = clientStatusIndex,
            ),
        keyStorageStatus =
            StatusListToken(
                statusList = keyStorageUri,
                index = keyStorageIndex,
            ),
    )

    @Test
    fun `no active credentials - nothing is revoked`() =
        runTest {
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> emptyList() },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID },
                    markStatusAsRevoked = { _ -> Unit.right() },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertTrue(revoked.isEmpty())
        }

    @Test
    fun `credential with all VALID statuses is not revoked`() =
        runTest {
            val credential = credential()
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertTrue(revoked.isEmpty())
        }

    @Test
    fun `credential with INVALID client status is revoked`() =
        runTest {
            val credential = credential()
            val revoked = mutableListOf<IssuedCredential>()
            val clientStatusUri = URI.create("https://example.com/status")
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { uri, _ ->
                        if (uri == clientStatusUri)
                            StatusListTokenStatus.INVALID
                        else
                            StatusListTokenStatus.VALID
                    },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertEquals(listOf(credential), revoked)
        }

    @Test
    fun `credential with INVALID key storage status is revoked`() =
        runTest {
            val keyStorageUri = URI.create("https://example.com/key-status")
            val credential = credential(keyStorageUri = keyStorageUri)
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { uri, _ ->
                        if (uri == keyStorageUri)
                            StatusListTokenStatus.INVALID
                        else
                            StatusListTokenStatus.VALID
                    },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertEquals(listOf(credential), revoked)
        }

    @Test
    fun `credential with INVALID client and key storage status is revoked only once`() =
        runTest {
            val credential = credential()
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.INVALID },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertEquals(1, revoked.size)
            assertEquals(credential, revoked.single())
        }

    @Test
    fun `error revoking one credential does not prevent processing of remaining credentials`() =
        runTest {
            val credential1 = credential(clientStatusUri = URI.create("https://example.com/status/1"))
            val credential2 = credential(clientStatusUri = URI.create("https://example.com/status/2"))
            val revoked = mutableListOf<IssuedCredential>()
            val markStatusAsRevokedCallCount = AtomicInteger(0)
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential1, credential2) },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.INVALID },
                    markStatusAsRevoked = { markStatusAsRevokedCallCount.incrementAndGet() },
                    deleteIssuedCredential = { credential ->
                        if (credential == credential1) throw RuntimeException("Persistence error")
                        revoked.add(credential)
                    },
                )

            useCase()

            assertEquals(2, markStatusAsRevokedCallCount.get())
            assertEquals(listOf(credential2), revoked)
        }

    @Test
    fun `when markStatusAsRevoked throws a runtime exception deleteIssuedCredential is not called`() =
        runTest {
            val credential = credential()
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.INVALID },
                    markStatusAsRevoked = { throw RuntimeException("External service unavailable") },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertTrue(revoked.isEmpty())
        }

    @Test
    fun `credential is not revoked when status verification fails`() =
        runTest {
            val credential = credential()
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { _, _ -> raise(GetStatusListTokenStatus.Error(RuntimeException("Network error"))) },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertTrue(revoked.isEmpty())
        }

    @Test
    fun `deleteExpiredIssuedCredentials failure propagates and prevents revocation processing`() =
        runTest {
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> throw RuntimeException("DB error") },
                    getNonExpiredIssuedCredentials = { _ -> emptyList() },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { },
                )

            assertTrue(
                runCatching { useCase() }.exceptionOrNull()?.message == "DB error",
            )
        }

    @Test
    fun `credential with null issuer status is revoked without calling markStatusAsRevoked`() =
        runTest {
            var markStatusAsRevokedCalled = false
            val credential =
                IssuedCredential(
                    format = Format("vc+sd-jwt"),
                    type = "eu.europa.ec.eudi.pid.1",
                    issuedAt = clock.now(),
                    expiresAt = clock.now() + 24.hours,
                    status = null,
                    clientStatus =
                        StatusListToken(
                            statusList = URI.create("https://example.com/status"),
                            index = 0u,
                        ),
                    keyStorageStatus = null,
                )
            val revoked = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> },
                    getNonExpiredIssuedCredentials = { _ -> listOf(credential) },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.INVALID },
                    markStatusAsRevoked = { markStatusAsRevokedCalled = true },
                    deleteIssuedCredential = { revoked.add(it) },
                )

            useCase()

            assertFalse(markStatusAsRevokedCalled)
            assertEquals(listOf(credential), revoked)
        }

    @Test
    fun `expired credentials are deleted before checking revocation status`() =
        runTest {
            val expiredCredential =
                IssuedCredential(
                    format = Format("vc+sd-jwt"),
                    type = "eu.europa.ec.eudi.pid.1",
                    issuedAt = clock.now() - 48.hours,
                    expiresAt = clock.now() - 24.hours,
                    status = null,
                    clientStatus =
                        StatusListToken(
                            statusList = URI.create("https://example.com/status"),
                            index = 0u,
                        ),
                    keyStorageStatus =
                        StatusListToken(
                            statusList = URI.create("https://example.com/key-status"),
                            index = 0u,
                        ),
                )
            val deleted = mutableListOf<IssuedCredential>()
            val useCase =
                RevokeCredentialsWithRevokedStatus(
                    clock = clock,
                    deleteExpiredIssuedCredentials = { _ -> deleted.add(expiredCredential) },
                    getNonExpiredIssuedCredentials = { _ -> emptyList() },
                    getStatusListTokenStatus = { _, _ -> StatusListTokenStatus.VALID },
                    markStatusAsRevoked = { _ -> },
                    deleteIssuedCredential = { },
                )

            useCase()

            assertEquals(listOf(expiredCredential), deleted)
        }
}
