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
package eu.europa.ec.eudi.pidissuer.adapter.out.credential

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import eu.europa.ec.eudi.pidissuer.domain.ClientStatus
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.KeyStorageStatus
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import kotlin.time.Instant

object CalculateCredentialExpiration {
    operator fun invoke(
        clientStatus: ClientStatus,
        keyStorageStatus: KeyStorageStatus,
        clock: Clock,
    ): Either<Unexpected, Instant> = either {
        val now = clock.now()
        ensure(clientStatus.expiresAt > now) { Unexpected("Client Status has expired") }
        ensure(keyStorageStatus.exp > now) { Unexpected("Key Storage Status has expired") }
        minOf(
            clientStatus.expiresAt,
            keyStorageStatus.exp,
        )
    }
}
