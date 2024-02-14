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
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.JWSAlgorithm

//
// Credential MetaData
//
typealias MsoDocType = String
typealias MsoNameSpace = String
typealias MsoMdocAttributeName = String

const val MSO_MDOC_FORMAT_VALUE = "mso_mdoc"
val MSO_MDOC_FORMAT = Format(MSO_MDOC_FORMAT_VALUE)
typealias MsoClaims = Map<MsoNameSpace, List<AttributeDetails>>

/**
 * @param docType string identifying the credential type as defined in ISO.18013-5.
 */
data class MsoMdocCredentialConfiguration(
    override val id: CredentialConfigurationId,
    val docType: MsoDocType,
    override val cryptographicBindingMethodsSupported: Set<CryptographicBindingMethod>,
    override val credentialSigningAlgorithmsSupported: Set<JWSAlgorithm>,
    override val scope: Scope? = null,
    override val display: List<CredentialDisplay> = emptyList(),
    val msoClaims: MsoClaims = emptyMap(),
    override val proofTypesSupported: NonEmptySet<ProofType>,
) : CredentialConfiguration

//
// Credential Request
//
data class MsoMdocCredentialRequest(
    override val unvalidatedProof: UnvalidatedProof,
    override val credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
    val docType: MsoDocType,
    val claims: Map<MsoNameSpace, List<MsoMdocAttributeName>> = emptyMap(),
) : CredentialRequest {
    override val format: Format = MSO_MDOC_FORMAT
}

context(Raise<String>)
internal fun MsoMdocCredentialRequest.validate(meta: MsoMdocCredentialConfiguration) {
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
