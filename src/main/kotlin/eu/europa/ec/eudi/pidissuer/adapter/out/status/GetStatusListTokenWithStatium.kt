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
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedIssuer
import eu.europa.ec.eudi.pidissuer.port.out.trust.VerificationContext
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
    val httpClient: HttpClient,
    val clock: Clock,
    val allowedClockSkew: Duration,
    val isTrustedIssuer: IsTrustedIssuer,
) : GetStatusListTokenStatus {
    context(_: Raise<GetStatusListTokenStatus.Error>)
    override suspend fun invoke(
        statusListToken: StatusListToken,
        verificationContext: VerificationContext,
    ): StatusListTokenStatus = catch({ read(statusListToken, verificationContext) }) { raise(GetStatusListTokenStatus.Error(it)) }

    private suspend fun read(
        statusListToken: StatusListToken,
        verificationContext: VerificationContext,
    ): StatusListTokenStatus {
        val verifyStatusListTokenSignature =
            VerifyStatusListTokenJwtSignature.usingTrust(
                isTrustedIssuer,
                verificationContext,
            )
        val getStatusListToken: GetStatusListToken =
            GetStatusListToken.usingJwt(clock, httpClient, verifyStatusListTokenSignature, allowedClockSkew)
        with(GetStatus(getStatusListToken)) {
            val statusReference =
                StatusReference(
                    index = StatusIndex(statusListToken.index.toInt()),
                    uri = statusListToken.statusList.toString(),
                )

            return statusReference.status(at = null).map { it.mapped() }.getOrThrow()
        }
    }

    private fun Status.mapped(): StatusListTokenStatus =
        when (this) {
            Status.Valid -> StatusListTokenStatus.VALID
            Status.Invalid -> StatusListTokenStatus.INVALID
            else -> error("Token status list contains an unsupported status $this")
        }
}
