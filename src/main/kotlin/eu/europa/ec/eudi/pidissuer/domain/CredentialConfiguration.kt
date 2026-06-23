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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptySet
import arrow.core.nonEmptySetOf
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.DeviceBinding.Required.ProofOption
import kotlinx.serialization.Serializable
import kotlin.time.Duration

/**
 * The unique identifier of an offered Credential.
 */
@JvmInline
value class CredentialConfigurationId(
    val value: String,
)

@JvmInline
@Serializable
value class AttackPotentialResistance(
    val value: String,
) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value

    @Suppress("unused")
    companion object {
        val Iso18045High: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_high")
        val Iso18045Moderate: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_moderate")
        val Iso18045EnhancedBasic: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_enhanced-basic")
        val Iso18045Basic: AttackPotentialResistance get() = AttackPotentialResistance("iso_18045_basic")
    }
}

data class KeyAttestationRequirement(
    val keyStorage: NonEmptySet<AttackPotentialResistance>?,
    val userAuthentication: NonEmptySet<AttackPotentialResistance>?,
    val preferredKeyStorageStatusPeriod: PreferredKeyStorageStatusPeriod,
) {
    companion object {
        fun ts3(preferredKeyStorageStatusPeriod: PreferredKeyStorageStatusPeriod): KeyAttestationRequirement =
            KeyAttestationRequirement(
                keyStorage = NonEmptySet.of(AttackPotentialResistance.Iso18045High),
                userAuthentication = NonEmptySet.of(AttackPotentialResistance.Iso18045High),
                preferredKeyStorageStatusPeriod = preferredKeyStorageStatusPeriod,
            )
    }
}

sealed interface ProofType {
    /**
     * A JWT is used as proof of possession.
     */
    data class Jwt(
        val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
        val keyAttestationRequirement: KeyAttestationRequirement,
    ) : ProofType

    data class Attestation(
        val signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
        val keyAttestationRequirement: KeyAttestationRequirement,
    ) : ProofType
}

sealed interface DeviceBinding {
    data object None : DeviceBinding

    data class Required constructor(
        val algorithmsSupported: NonEmptySet<JWSAlgorithm>,
        val keyStorageRequirement: KeyAttestationRequirement,
        val proofType: ProofOption = ProofOption.Either,
    ) : DeviceBinding {
        enum class ProofOption {
            ProofJwtWithKeyAttestation,
            ProofKeyAttestation,
            Either,
        }

        fun proofTypesSupported(): NonEmptySet<ProofType> {
            fun jwtWithKA() = ProofType.Jwt(algorithmsSupported, keyStorageRequirement)

            fun attestation() = ProofType.Attestation(algorithmsSupported, keyStorageRequirement)
            return when (proofType) {
                ProofOption.ProofJwtWithKeyAttestation -> nonEmptySetOf(jwtWithKA(), attestation())
                ProofOption.ProofKeyAttestation -> nonEmptySetOf(attestation())
                ProofOption.Either -> nonEmptySetOf(jwtWithKA(), attestation())
            }
        }
    }

    companion object {
        val AllowedAlgorithms = nonEmptySetOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)

        fun ts3(
            algorithmsSupported: NonEmptySet<JWSAlgorithm> = AllowedAlgorithms,
            preferredKeyStorageStatusPeriod: PreferredKeyStorageStatusPeriod,
        ): Required {
            require(algorithmsSupported.all { it in AllowedAlgorithms }) {
                "Only EC signing algorithms are supported."
            }
            return Required(
                algorithmsSupported,
                KeyAttestationRequirement.ts3(preferredKeyStorageStatusPeriod),
                ProofOption.Either,
            )
        }
    }
}

/**
 * Representing metadata about a separate credential type
 * that the Credential Issuer can issue
 */
sealed interface CredentialConfiguration {
    val id: CredentialConfigurationId
    val scope: Scope
    val display: List<CredentialDisplay>
    val cryptographicBindingMethodsSupported: NonEmptySet<CryptographicBindingMethod>?
    val deviceBinding: DeviceBinding
    val category: AttestationCategory
    val reusePolicy: CredentialReusePolicy
    val validity: Duration
}
