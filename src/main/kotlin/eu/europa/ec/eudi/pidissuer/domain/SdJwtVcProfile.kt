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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.nimbusds.jose.JWSAlgorithm

/**
 * @see https://vcstuff.github.io/oid4vc-haip-sd-jwt-vc/draft-oid4vc-haip-sd-jwt-vc.html#name-format-identifier
 */
const val SD_JWT_VC_FORMAT = "vc+sd-jwt"

@JvmInline
value class SdJwtVcType(val value: String)

/**
 * @param type As defined in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-00#type-claim
 */
data class SdJwtVcMetaData(
    val type: SdJwtVcType,
    override val scope: Scope? = null,
    val cryptographicSuitesSupported: List<JWSAlgorithm>,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val display: List<CredentialDisplay>,
    val claims: List<AttributeDetails>,
) : CredentialMetaData {
    override val format: Format = Format(SD_JWT_VC_FORMAT)
}

//
// Credential Offer
//
data class SdJwtVcCredentialRequest(
    val type: SdJwtVcType,
    val claims: List<AttributeDetails> = emptyList(),
) : CredentialRequestFormat

fun SdJwtVcCredentialRequest.validate(meta: SdJwtVcMetaData): Either<String, Unit> = either {
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
