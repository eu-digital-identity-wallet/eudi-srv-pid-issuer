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

//
// Credential MetaData
//

const val JWT_VS_JSON_FORMAT_VALUE = "jwt_vc_json"
val JWT_VS_JSON_FORMAT = Format(JWT_VS_JSON_FORMAT_VALUE)

/**
 * W3C VC signed as a JWT, not using JSON-LD (jwt_vc_json)
 */
data class JwtVcJsonCredentialConfiguration(
    override val id: CredentialConfigurationId,
    override val scope: Scope,
    val credentialSigningAlgorithmsSupported: NonEmptySet<JWSAlgorithm>?,
    override val display: List<CredentialDisplay>,
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

//
// Credential Offer
//

@Suppress("unused")
object DummyJwtVc
