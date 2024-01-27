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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptySet
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm

/**
 * The unique identifier of an offered Credential.
 */
@JvmInline
value class CredentialConfigurationId(val value: String)

enum class ProofType {
    JWT,
    CWT,
}

/**
 * Representing metadata about a separate credential type
 * that the Credential Issuer can issue
 */
sealed interface CredentialConfiguration {
    val id: CredentialConfigurationId
    val format: Format
    val scope: Scope?
    val display: List<CredentialDisplay>
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
    val proofTypesSupported: Set<ProofType>
}

fun CredentialConfiguration.cryptographicSuitesSupported(): NonEmptySet<JWSAlgorithm> {
    val suites = cryptographicBindingMethodsSupported.map { method ->
        when (method) {
            is CryptographicBindingMethod.CoseKey -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.DidAnyMethod -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.DidMethod -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.Jwk -> method.cryptographicSuitesSupported
            is CryptographicBindingMethod.Mso -> method.cryptographicSuitesSupported
        }
    }.flatten().toNonEmptySetOrNull()
    return checkNotNull(suites)
}
