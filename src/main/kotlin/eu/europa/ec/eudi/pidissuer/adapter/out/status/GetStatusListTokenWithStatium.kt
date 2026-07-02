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

import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.raise
import com.eygraber.uri.Uri
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import eu.europa.ec.eudi.statium.*
import io.ktor.client.*
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Duration

private val logger = LoggerFactory.getLogger(GetStatusListTokenWithStatium::class.java)

/**
 * Checks the status of a single entry in a Token Status List using the statium library.
 */
class GetStatusListTokenWithStatium(
    private val getStatus: GetStatus,
) : GetStatusListTokenStatus {
    context(_: Raise<GetStatusListTokenStatus.Error>)
    override suspend fun invoke(
        uri: Uri,
        index: UInt,
    ): StatusListTokenStatus = catch({ getStatus.read(uri, index) }) { raise(GetStatusListTokenStatus.Error(it)) }

    companion object {
        val NotValidating: VerifyStatusListTokenJwtSignature = { _, _ ->
            logger.warn("Not validating status list token signature!!!")
            Result.success(Unit)
        }

        operator fun invoke(
            httpClient: HttpClient,
            clock: Clock,
            verifyStatusListTokenSignature: VerifyStatusListTokenJwtSignature = NotValidating,
            allowedClockSkew: Duration,
        ): GetStatusListTokenWithStatium {
            val getStatusListToken: GetStatusListToken =
                GetStatusListToken.usingJwt(clock, httpClient, verifyStatusListTokenSignature)
            val getStatus = GetStatus(getStatusListToken)
            return GetStatusListTokenWithStatium(getStatus)
        }

        private suspend fun GetStatus.read(
            uri: Uri,
            index: UInt,
        ): StatusListTokenStatus {
            val statusReference =
                StatusReference(
                    index = StatusIndex(index.toInt()),
                    uri = uri.toString(),
                )
            return statusReference.status(at = null).map { it.mapped() }.getOrThrow()
        }

        private fun Status.mapped(): StatusListTokenStatus =
            when (this) {
                Status.Valid -> StatusListTokenStatus.VALID
                Status.Invalid -> StatusListTokenStatus.INVALID
                else -> error("Token status list contains an unsupported status $this")
            }
    }
}
