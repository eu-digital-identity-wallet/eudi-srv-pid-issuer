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
package eu.europa.ec.eudi.pidissuer.port.out.status

import arrow.core.Either
import java.net.URI

/**
 * The status of a single entry in a Token Status List.
 * Per the Token Status List spec, 0 = VALID, 1 = INVALID (revoked).
 */
enum class StatusListTokenStatus {
    VALID,
    INVALID,
}

fun interface GetStatusListTokenStatus {
    /**
     * Checks the status of a single entry in a Token Status List.
     *
     * @param uri the URI of the status list token
     * @param index the index of the entry within the status list
     */
    suspend operator fun invoke(
        uri: URI,
        index: UInt,
    ): Either<Throwable, StatusListTokenStatus>
}
