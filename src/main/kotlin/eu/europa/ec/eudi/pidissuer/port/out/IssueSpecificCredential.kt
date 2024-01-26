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

import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreDeferredCredential
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory

interface IssueSpecificCredential<out T> {

    val supportedCredential: CredentialConfiguration
    val publicKey: JWK?

    context(Raise<IssueCredentialError>)
    suspend operator fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<T>
}

fun IssueSpecificCredential<JsonElement>.asDeferred(
    generateTransactionId: GenerateTransactionId,
    storeDeferredCredential: StoreDeferredCredential,
): IssueSpecificCredential<JsonElement> =
    DeferredIssuer(this, generateTransactionId, storeDeferredCredential)

private class DeferredIssuer(
    val issuer: IssueSpecificCredential<JsonElement>,
    val generateTransactionId: GenerateTransactionId,
    val storeDeferredCredential: StoreDeferredCredential,
) : IssueSpecificCredential<JsonElement> by issuer {

    private val log = LoggerFactory.getLogger(DeferredIssuer::class.java)
    context(Raise<IssueCredentialError>) override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> {
        val credentialResponse = issuer.invoke(authorizationContext, request, expectedCNonce)
        require(credentialResponse is CredentialResponse.Issued<JsonElement>) { "Actual issuer should return issued credentials" }

        val transactionId = generateTransactionId()
        storeDeferredCredential(transactionId, credentialResponse)
        return CredentialResponse.Deferred(credentialResponse.format, transactionId).also {
            log.info("Repackaged $credentialResponse  as $it")
        }
    }
}
