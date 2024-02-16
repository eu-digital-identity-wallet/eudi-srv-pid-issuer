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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.raise.Raise
import eu.europa.ec.eudi.pidissuer.domain.TransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialByTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialResult
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory

@Serializable
data class DeferredCredentialRequestTO(
    @Required @SerialName("transaction_id") val transactionId: String,
)

@Serializable
data class CredentialTO(
    @Required val credential: JsonElement,
    @SerialName("notification_id") @Required val notificationId: String,
)

@Serializable
data class GetDeferredCredentialErrorTO(val error: String) {
    companion object {
        val IssuancePending = GetDeferredCredentialErrorTO("issuance_pending")
        val InvalidTransactionId = GetDeferredCredentialErrorTO("invalid_transaction_id")
    }
}

/**
 * Usecase for retrieving/polling a deferred credential
 */
class GetDeferredCredential(val loadDeferredCredentialByTransactionId: LoadDeferredCredentialByTransactionId) {

    private val log = LoggerFactory.getLogger(GetDeferredCredential::class.java)

    context (Raise<GetDeferredCredentialErrorTO>)
    suspend operator fun invoke(requestTO: DeferredCredentialRequestTO): CredentialTO = coroutineScope {
        val transactionId = TransactionId(requestTO.transactionId)
        log.info("GetDeferredCredential for $transactionId ...")
        loadDeferredCredentialByTransactionId(transactionId).toTo()
    }
}

context (Raise<GetDeferredCredentialErrorTO>)
private fun LoadDeferredCredentialResult.toTo(): CredentialTO = when (this) {
    is LoadDeferredCredentialResult.IssuancePending -> raise(GetDeferredCredentialErrorTO.IssuancePending)
    is LoadDeferredCredentialResult.InvalidTransactionId -> raise(GetDeferredCredentialErrorTO.InvalidTransactionId)
    is LoadDeferredCredentialResult.Found -> CredentialTO(credential.credential, credential.notificationId.value)
}
