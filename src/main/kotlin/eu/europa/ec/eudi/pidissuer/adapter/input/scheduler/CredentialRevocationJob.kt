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
package eu.europa.ec.eudi.pidissuer.adapter.input.scheduler

import eu.europa.ec.eudi.pidissuer.port.input.RevokeCredentialsWithRevokedStatus
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(CredentialRevocationJob::class.java)

/**
 * Periodic Spring job that checks all active issued credentials against their
 * client status and key storage status lists and revokes any that have been invalidated.
 *
 * The schedule can be configured via the `issuer.revocation.job.cron` property
 * (default: every 8 hours).
 */
class CredentialRevocationJob(
    private val revokeCredentialsWithRevokedStatus: RevokeCredentialsWithRevokedStatus,
) {
    suspend fun run() {
        log.info("Starting credential revocation job")

        runCatching { revokeCredentialsWithRevokedStatus() }
            .onFailure { log.error("Credential revocation job failed", it) }
            .onSuccess { log.info("Credential revocation job completed successfully") }
    }
}
