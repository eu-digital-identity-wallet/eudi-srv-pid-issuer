/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.pidissuer.port.out

import arrow.core.Either
import arrow.core.raise.either
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreDeferredCredential
import org.slf4j.LoggerFactory
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

interface IssueSpecificCredential {

    val supportedCredential: CredentialConfiguration
    val publicKey: JWK?
    val keyAttestationRequirement: KeyAttestationRequirement

    suspend operator fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse>
}

fun IssueSpecificCredential.asDeferred(
    generateTransactionId: GenerateTransactionId,
    storeDeferredCredential: StoreDeferredCredential,
    clock: Clock,
    interval: Duration = 1.minutes,
): IssueSpecificCredential =
    DeferredIssuer(this, generateTransactionId, storeDeferredCredential, clock, interval)

private class DeferredIssuer(
    val issuer: IssueSpecificCredential,
    val generateTransactionId: GenerateTransactionId,
    val storeDeferredCredential: StoreDeferredCredential,
    val clock: Clock,
    val interval: Duration,
) : IssueSpecificCredential by issuer {

    override val supportedCredential: CredentialConfiguration
        get() = when (val cfg = issuer.supportedCredential) {
            is JwtVcJsonCredentialConfiguration -> cfg.copy(
                id = CredentialConfigurationId(cfg.id.value + "_deferred"),
                display = cfg.display.map { it.copy(name = it.name.copy(name = it.name.name + " (deferred)")) },
            )
            is MsoMdocCredentialConfiguration -> cfg.copy(
                id = CredentialConfigurationId(cfg.id.value + "_deferred"),
                display = cfg.display.map { it.copy(name = it.name.copy(name = it.name.name + " (deferred)")) },
            )
            is SdJwtVcCredentialConfiguration -> cfg.copy(
                id = CredentialConfigurationId(cfg.id.value + "_deferred"),
                display = cfg.display.map { it.copy(name = it.name.copy(name = it.name.name + " (deferred)")) },
            )
        }

    private val log = LoggerFactory.getLogger(DeferredIssuer::class.java)

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        val credentialResponse =
            issuer.invoke(authorizationContext, request, credentialIdentifier).bind()

        require(credentialResponse is CredentialResponse.Issued) { "Actual issuer should return issued credentials" }

        val transactionId = generateTransactionId()
        val notIssuedBefore = clock.now() + interval
        storeDeferredCredential.invoke(transactionId, credentialResponse, notIssuedBefore)
        CredentialResponse.Deferred(transactionId, interval).also {
            log.info("Repackaged $credentialResponse  as $it")
        }
    }
}
