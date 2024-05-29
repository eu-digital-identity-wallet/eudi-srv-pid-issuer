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
package eu.europa.ec.eudi.pidissuer.adapter.out.persistence

import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.TransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialByTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialResult
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreDeferredCredential
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(InMemoryDeferredCredentialRepository::class.java)
class InMemoryDeferredCredentialRepository(
    private val data: MutableMap<TransactionId, Pair<CredentialResponse.Issued<JsonElement>, RequestedResponseEncryption>?> =
        mutableMapOf(),
) {

    private val mutex = Mutex()

    val loadDeferredCredentialByTransactionId: LoadDeferredCredentialByTransactionId =
        LoadDeferredCredentialByTransactionId { transactionId ->
            mutex.withLock(this) {
                if (data.containsKey(transactionId)) {
                    data[transactionId]
                        ?.let { (credential, encryption) -> LoadDeferredCredentialResult.Found(credential, encryption) }
                        ?: LoadDeferredCredentialResult.IssuancePending
                } else LoadDeferredCredentialResult.InvalidTransactionId
            }
        }

    val storeDeferredCredential: StoreDeferredCredential =
        StoreDeferredCredential { transactionId, credential, responseEncryption ->
            mutex.withLock(this) {

                if (data.containsKey(transactionId)) {
                    require(data[transactionId] == null) { "Oops!! $transactionId already exists" }
                }
                data[transactionId] = credential to responseEncryption

                log.info("Stored $transactionId -> $credential ")
            }
        }
}
