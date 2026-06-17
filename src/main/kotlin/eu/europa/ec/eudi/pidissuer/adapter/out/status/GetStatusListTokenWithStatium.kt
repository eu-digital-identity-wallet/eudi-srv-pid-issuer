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
package eu.europa.ec.eudi.pidissuer.adapter.out.status

import arrow.core.Either
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import eu.europa.ec.eudi.statium.GetStatus
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.statium.Status
import eu.europa.ec.eudi.statium.StatusIndex
import eu.europa.ec.eudi.statium.StatusReference
import io.ktor.client.HttpClient
import java.net.URI
import kotlin.time.Instant

/**
 * Checks the status of a single entry in a Token Status List using the statium library.
 */
internal class GetStatusListTokenWithStatium(
    private val httpClient: HttpClient,
    private val clock: Clock,
) : GetStatusListTokenStatus {
    override suspend fun invoke(
        uri: URI,
        index: UInt,
    ): Either<Throwable, StatusListTokenStatus> =
        Either.catch {
            val getStatusListToken =
                GetStatusListToken.usingJwt(
                    clock =
                        object : kotlin.time.Clock {
                            override fun now(): Instant = clock.now()
                        },
                    httpClient = httpClient,
                    verifyStatusListTokenSignature = { _, _ ->
                        Result.success(Unit) // TODO
                    },
                )
            val getStatus = GetStatus(getStatusListToken)
            val statusReference =
                StatusReference(
                    index = StatusIndex(index.toInt()),
                    uri = uri.toString(),
                )
            val status =
                with(getStatus) {
                    statusReference.status(at = null).getOrThrow()
                }
            if (status == Status.Valid) StatusListTokenStatus.VALID else StatusListTokenStatus.INVALID
        }
}
