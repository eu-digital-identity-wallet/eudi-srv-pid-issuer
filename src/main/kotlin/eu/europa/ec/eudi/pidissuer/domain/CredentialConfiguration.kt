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
import com.nimbusds.jose.JWSAlgorithm

/**
 * The unique identifier of an offered Credential.
 */
@JvmInline
value class CredentialConfigurationId(val value: String)

sealed interface ProofType {

    val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>

    /**
     * A JWT is used as proof of possession.
     */
    data class Jwt(override val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>) : ProofType

    /**
     *  A CWT is used as proof of possession.
     */
    data class Cwt(override val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>) : ProofType

    /**
     * A W3C Verifiable Presentation object signed using the Data Integrity Proof is used as proof of possession.
     */
    data class LdpVp(override val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>) : ProofType
}

/**
 * Representing metadata about a separate credential type
 * that the Credential Issuer can issue
 */
sealed interface CredentialConfiguration {
    val id: CredentialConfigurationId
    val scope: Scope?
    val display: List<CredentialDisplay>
    val cryptographicBindingMethodsSupported: Set<CryptographicBindingMethod>
    val credentialSigningAlgorithmsSupported: Set<JWSAlgorithm>
    val proofTypesSupported: Set<ProofType>
}
