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
package eu.europa.ec.eudi.pidissuer.port.out.credential

import kotlin.time.Instant

/**
 * Verifies a Nonce value is valid at a specific [Instant].
 */
fun interface VerifyNonce {
    suspend operator fun invoke(value: String?, at: Instant): Boolean

    suspend operator fun invoke(values: List<String?>, at: Instant): Boolean =
        when (values.distinct().size) {
            1 -> this(values.first(), at)
            else -> false
        }

    companion object {

        /**
         * Gets a [VerifyNonce] that perform no verification.
         */
        fun noCNonceRequired(): VerifyNonce = VerifyNonce { _, _ -> true }
    }
}
