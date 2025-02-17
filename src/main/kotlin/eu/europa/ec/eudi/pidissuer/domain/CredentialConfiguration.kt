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

@JvmInline
value class AttackPotentialResistance(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value

    companion object {
        val Iso18045High: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_high")
        val Iso18045Moderate: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_moderate")
        val Iso18045EnhancedBasic: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_enhanced-basic")
        val Iso18045Basic: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_basic")
    }
}

sealed interface KeyAttestation {

    data object NotRequired : KeyAttestation

    data class Required(
        val keyStorage: NonEmptySet<AttackPotentialResistance>?,
        val useAuthentication: NonEmptySet<AttackPotentialResistance>?,
    ) : KeyAttestation
}

sealed interface ProofType {

    /**
     * A JWT is used as proof of possession.
     */
    data class Jwt(
        val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
        val keyAttestation: KeyAttestation,
    ) : ProofType
}

fun ProofType.type(): ProofTypeEnum = when (this) {
    is ProofType.Jwt -> ProofTypeEnum.JWT
}
enum class ProofTypeEnum {
    JWT,
}

@JvmInline
value class ProofTypesSupported private constructor(val values: Set<ProofType>) {

    operator fun get(type: ProofTypeEnum): ProofType? = values.firstOrNull { it.type() == type }

    companion object {
        val Empty: ProofTypesSupported = ProofTypesSupported(emptySet())
        operator fun invoke(values: Set<ProofType>): ProofTypesSupported {
            require(values.groupBy(ProofType::type).all { (_, instances) -> instances.size == 1 }) {
                "Multiple instance of the same proof type are not allowed"
            }
            return ProofTypesSupported(values)
        }
    }
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
    val proofTypesSupported: ProofTypesSupported
}
