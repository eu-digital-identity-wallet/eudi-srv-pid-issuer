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

/**
 * @see https://vcstuff.github.io/oid4vc-haip-sd-jwt-vc/draft-oid4vc-haip-sd-jwt-vc.html#name-format-identifier
 */
const val SD_JWT_VC_FORMAT_VALUE = "vc+sd-jwt"
val SD_JWT_VC_FORMAT = Format(SD_JWT_VC_FORMAT_VALUE)

@JvmInline
value class SdJwtVcType(val value: String)

/**
 * @param type As defined in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-00#type-claim
 */
data class SdJwtVcCredentialConfiguration(
    override val id: CredentialConfigurationId,
    val type: SdJwtVcType,
    override val scope: Scope? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val display: List<CredentialDisplay>,
    val claims: List<AttributeDetails>,
    override val proofTypesSupported: Set<ProofType>,
) : CredentialConfiguration

//
// Credential Offer
//
data class SdJwtVcCredentialRequest(
    override val unvalidatedProof: UnvalidatedProof,
    override val credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
    val type: SdJwtVcType,
    val claims: List<AttributeDetails> = emptyList(),
) : CredentialRequest {
    override val format: Format = SD_JWT_VC_FORMAT
}

context(Raise<String>)
internal fun SdJwtVcCredentialRequest.validate(meta: SdJwtVcCredentialConfiguration) {
    ensure(type == meta.type) { "doctype is $type but was expecting ${meta.type}" }
    if (meta.claims.isEmpty()) {
        ensure(claims.isEmpty()) { "Requested claims should be empty. " }
    } else {
        val expectedAttributeNames = meta.claims.map { it.name }
        claims.forEach { attr ->
            ensure(expectedAttributeNames.contains(attr.name)) { "Unexpected attribute $attr" }
        }
    }
}
