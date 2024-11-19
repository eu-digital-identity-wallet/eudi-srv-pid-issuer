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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.Username

fun interface GetPidData {
    suspend operator fun invoke(username: Username): Pair<Pid, PidMetaData>?

    suspend operator fun invoke(authorizationContext: AuthorizationContext):
        Either<IssueCredentialError.Unexpected, Pair<Pid, PidMetaData>> = either {
        val data = invoke(authorizationContext.username)
        ensureNotNull(data) { IssueCredentialError.Unexpected("Cannot obtain data") }
    }
}
