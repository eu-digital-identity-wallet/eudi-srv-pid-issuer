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
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.JWSAlgorithm

//
// Credential MetaData
//
typealias MsoDocType = String
typealias MsoNameSpace = String
typealias MsoMdocAttributeName = String

data class MsoMdocAttribute<out V>(val name: MsoMdocAttributeName, val value: V)

const val MSO_MDOC_FORMAT = "mso_mdoc"

typealias MsoClaims = Map<MsoNameSpace, List<AttributeDetails>>

/**
 * @param docType string identifying the credential type as defined in ISO.18013-5.
 */
data class MsoMdocMetaData(
    val docType: MsoDocType,
    val cryptographicSuitesSupported: List<JWSAlgorithm>,
    override val scope: Scope? = null,
    override val display: List<CredentialDisplay> = emptyList(),
    val msoClaims: MsoClaims = emptyMap(),
) : CredentialMetaData {
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
        get() = listOf(CryptographicBindingMethod.Mso(cryptographicSuitesSupported))

    override val format: Format = Format(MSO_MDOC_FORMAT)
}

//
// Credential Offer
//

data class MsoMdocCredentialOffer(val docType: MsoDocType) : CredentialOffer

data class MsoMdoc(
    val docType: MsoDocType,
    val attributes: Map<MsoNameSpace, MsoMdocAttribute<Any>>,
)

//
// Credential Request
//
data class MsmMdocCredentialRequest(
    val docType: MsoDocType,
    val claims: Map<MsoNameSpace, List<MsoMdocAttributeName>> = emptyMap(),
) : CredentialRequestFormat

fun MsmMdocCredentialRequest.validate(meta: MsoMdocMetaData): Either<String, Unit> = either {
    ensure(docType == meta.docType) { "doctype is $docType but was expecting ${meta.docType}" }
    if (meta.msoClaims.isEmpty()) {
        ensure(claims.isEmpty()) { "Requested claims should be empty. " }
    } else {
        val expectedAttributeNames = meta.msoClaims.mapValues { kv -> kv.value.map { it.name } }
        claims.forEach { (namespace, attributes) ->
            val expectedAttributeNamesForNamespace = expectedAttributeNames[namespace]
            ensureNotNull(expectedAttributeNamesForNamespace) { "Unexpected namespace $namespace" }
            attributes.forEach { attr ->
                ensure(expectedAttributeNamesForNamespace.contains(attr)) { "Unexpected attribute $attr for namespace $namespace" }
            }
        }
    }
}
