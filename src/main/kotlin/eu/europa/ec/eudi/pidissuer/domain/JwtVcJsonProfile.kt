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
import com.nimbusds.jwt.SignedJWT as NimbusSignedJWT

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
    override val cryptographicBindingMethodsSupported: Set<CryptographicBindingMethod>,
    val credentialSigningAlgorithmsSupported: NonEmptySet<JWSAlgorithm>?,
    override val display: List<CredentialDisplay>,
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
) : CredentialConfiguration {
    init {
        validateCryptographicBindingsAndProofTypes()
    }
}

//
// Credential Offer
//

object DummyJwtVc

/**
 * A W3C VC signed as a JWT, not using JSON-LD, Issued Credential.
 */
@JvmInline
value class JwtVcIssuedCredential(val credential: NimbusSignedJWT)
