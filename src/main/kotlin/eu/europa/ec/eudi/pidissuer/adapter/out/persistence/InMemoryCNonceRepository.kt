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

import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteCNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadCNonceByAccessToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.UpsertCNonce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class InMemoryCNonceRepository : DeleteCNonce, LoadCNonceByAccessToken, UpsertCNonce {

    private val data = ConcurrentHashMap<String, CNonce>()
    private val mutex = Mutex()

    override suspend fun invoke(at: Instant): Unit =
        mutex.withLock(this) {
            val matching = data.entries
                .filter { (it.value.activatedAt + it.value.expiresIn) <= at }
                .map { it.key }
            matching.forEach { data.remove(it) }
        }

    override suspend fun invoke(accessToken: String): CNonce? =
        mutex.withLock(this) {
            data[accessToken]
        }

    override suspend fun invoke(cNonce: CNonce): Unit =
        mutex.withLock(this) {
            data[cNonce.accessToken] = cNonce
        }

    internal suspend fun clear(): Unit =
        mutex.withLock(this) {
            data.clear()
        }

    internal suspend fun verify(verifier: suspend (Map<String, CNonce>) -> Unit): Unit =
        mutex.withLock(this) {
            verifier(data)
        }
}
