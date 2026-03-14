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
package eu.europa.ec.eudi.pidissuer.adapter.out.simplecredential

import kotlin.time.Instant

@JvmInline
value class SimpleNonBlankString(val value: String) {
    init {
        require(value.isNotBlank())
    }

    override fun toString(): String = value
}

typealias SimpleFamilyName = SimpleNonBlankString
typealias SimpleGivenName = SimpleNonBlankString
typealias SimpleEmail = SimpleNonBlankString
typealias SimpleDateOfBirth = SimpleNonBlankString

data class SimpleCredential(
    val familyName: SimpleFamilyName,
    val givenName: SimpleGivenName,
    val email: SimpleEmail,
    val dateOfBirth: SimpleDateOfBirth,
    val issuanceDate: Instant,
) {
    companion object
}
