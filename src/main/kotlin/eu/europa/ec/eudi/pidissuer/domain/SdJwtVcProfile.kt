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
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import kotlin.time.Duration

const val SD_JWT_VC_FORMAT_VALUE = SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT
val SD_JWT_VC_FORMAT = Format(SD_JWT_VC_FORMAT_VALUE)

@JvmInline
value class SdJwtVcType(
    val value: String,
)

data class SdJwtVcCredentialConfiguration(
    override val id: CredentialConfigurationId,
    override val scope: Scope,
    override val display: List<CredentialDisplay>,
    override val deviceBinding: DeviceBinding,
    override val category: AttestationCategory,
    override val reusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    override val validity: Duration,
    val type: SdJwtVcType,
    val credentialSigningAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
    val publicKey: JWK,
    val claims: List<ClaimDefinition>,
) : CredentialConfiguration {
    init {
        require(validity.isPositive()) { "'validity' must be a positive duration" }
        if (deviceBinding is DeviceBinding.Required) {
            val preferredKeyStorageStatusPeriod = deviceBinding.keyStorageRequirement.preferredKeyStorageStatusPeriod
            require(validity <= preferredKeyStorageStatusPeriod.value) {
                "'validity' must be less than or equal to the preferred key storage status period"
            }
        }
    }

    override val cryptographicBindingMethodsSupported: NonEmptySet<CryptographicBindingMethod>?
        get() =
            when (deviceBinding) {
                DeviceBinding.None -> null
                is DeviceBinding.Required -> nonEmptySetOf(CryptographicBindingMethod.Jwk)
            }
}
