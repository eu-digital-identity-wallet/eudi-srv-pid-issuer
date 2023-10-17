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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.domain.pid.Pid
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

sealed interface HelloHolderError {
    data object NotFound : HelloHolderError
}

class HelloHolder(private val getPidData: GetPidData) {
    suspend operator fun invoke(accessToken: String): Either<HelloHolderError, Pid> =
        coroutineScope {
            val waiting = async { getPidData(accessToken) }
            either {
                val pid = waiting.await()
                ensureNotNull(pid) { HelloHolderError.NotFound }
            }
        }
}
