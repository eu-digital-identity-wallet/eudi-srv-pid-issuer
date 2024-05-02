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

import arrow.core.raise.Raise
import arrow.core.raise.ensure
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT as NimbusSignedJWT

//
// Credential MetaData
//

const val JWT_VC_JSON_FORMAT_VALUE = "jwt_vc_json"
val JWT_VC_JSON_FORMAT = Format(JWT_VC_JSON_FORMAT_VALUE)

/**
 * W3C VC signed as a JWT, not using JSON-LD (jwt_vc_json)
 */
data class JwtVcJsonCredentialConfiguration(
    override val id: CredentialConfigurationId,
    override val scope: Scope? = null,
    override val cryptographicBindingMethodsSupported: Set<CryptographicBindingMethod>,
    override val credentialSigningAlgorithmsSupported: Set<JWSAlgorithm>,
    override val display: List<CredentialDisplay>,
    override val proofTypesSupported: Set<ProofType>,
    val credentialDefinition: CredentialDefinition,
    val order: List<String>? = null,
) : CredentialConfiguration

data class CredentialDefinition(
    val type: List<String>,
    val credentialSubject: List<AttributeDetails>?,
)

//
// Credential Request
//
data class JwtVcJsonCredentialRequest(
    override val unvalidatedProof: UnvalidatedProof,
    override val credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
    val credentialDefinition: CredentialDefinitionRequested,
) : CredentialRequest {
    override val format: Format = JWT_VC_JSON_FORMAT
}

data class CredentialDefinitionRequested(
    val type: List<String>,
    val credentialSubject: List<String>?,
)

context(Raise<String>)
internal fun JwtVcJsonCredentialRequest.validate(meta: JwtVcJsonCredentialConfiguration) {
    ensure(meta.credentialDefinition.type.containsAll(credentialDefinition.type)) {
        "type is ${credentialDefinition.type} but was expecting ${meta.credentialDefinition.type}"
    }
    if (meta.credentialDefinition.credentialSubject.isNullOrEmpty()) {
        ensure(credentialDefinition.credentialSubject.isNullOrEmpty()) { "Requested claims should be empty." }
    } else {
        val submittedClaims = credentialDefinition.credentialSubject
        val expectedClaims = meta.credentialDefinition.credentialSubject.map { it.name }
        submittedClaims?.let {
            ensure(expectedClaims.containsAll(submittedClaims)) { "Unexpected claim name requested" }
        }
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
