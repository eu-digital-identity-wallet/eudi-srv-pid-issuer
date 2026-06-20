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
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec

const val SD_JWT_VC_FORMAT_VALUE = SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT
val SD_JWT_VC_FORMAT = Format(SD_JWT_VC_FORMAT_VALUE)

@JvmInline
value class SdJwtVcType(
    val value: String,
)

/**
 * @param type As defined in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-00#type-claim
 */
data class SdJwtVcCredentialConfiguration(
    override val id: CredentialConfigurationId,
    val type: SdJwtVcType,
    override val scope: Scope,
    val credentialSigningAlgorithmsSupported: NonEmptySet<JWSAlgorithm>?,
    override val display: List<CredentialDisplay>,
    val claims: List<ClaimDefinition>,
    override val deviceBinding: DeviceBinding,
    override val attestationCategory: AttestationCategory,
    override val credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
) : CredentialConfiguration {
    override val cryptographicBindingMethodsSupported: NonEmptySet<CryptographicBindingMethod>?
        get() =
            when (deviceBinding) {
                DeviceBinding.None -> null
                is DeviceBinding.Required -> nonEmptySetOf(CryptographicBindingMethod.Jwk)
            }
}
