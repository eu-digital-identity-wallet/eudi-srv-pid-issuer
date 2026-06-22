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
package eu.europa.ec.eudi.pidissuer.port.out.attestation

import arrow.core.raise.Raise
import eu.europa.ec.eudi.pidissuer.domain.AuthorizedCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreDeferredCredential
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

fun AttestationIssuer.asDeferred(
    generateTransactionId: GenerateTransactionId,
    storeDeferredCredential: StoreDeferredCredential,
    clock: Clock,
    interval: Duration = 1.minutes,
): AttestationIssuer = DeferredIssuer(this, generateTransactionId, storeDeferredCredential, clock, interval)

private class DeferredIssuer(
    val issuer: AttestationIssuer,
    val generateTransactionId: GenerateTransactionId,
    val storeDeferredCredential: StoreDeferredCredential,
    val clock: Clock,
    val interval: Duration,
) : AttestationIssuer by issuer {
    override val configuration: CredentialConfiguration
        get() =
            when (val cfg = issuer.configuration) {

                is MsoMdocCredentialConfiguration -> {
                    cfg.copy(
                        id = CredentialConfigurationId(cfg.id.value + "_deferred"),
                        display = cfg.display.map { it.copy(name = it.name.copy(name = it.name.name + " (deferred)")) },
                    )
                }

                is SdJwtVcCredentialConfiguration -> {
                    cfg.copy(
                        id = CredentialConfigurationId(cfg.id.value + "_deferred"),
                        display = cfg.display.map { it.copy(name = it.name.copy(name = it.name.name + " (deferred)")) },
                    )
                }
            }

    private val log = LoggerFactory.getLogger(DeferredIssuer::class.java)

    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        val credentialResponse = issuer.invoke(request)

        // That's a runtime exception because it would be a bug in the issuer
        check(credentialResponse is CredentialResponse.Issued) {
            "Actual issuer should return issued credentials"
        }
        val transactionId = generateTransactionId()
        val notIssuedBefore = clock.now() + interval
        storeDeferredCredential.invoke(transactionId, credentialResponse, notIssuedBefore)
        val deferred = CredentialResponse.Deferred(transactionId, interval)
        log.info("Repackaged $credentialResponse  as $deferred")
        return deferred
    }
}
