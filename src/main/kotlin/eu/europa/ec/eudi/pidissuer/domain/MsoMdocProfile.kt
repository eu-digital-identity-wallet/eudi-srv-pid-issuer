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

import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.ensure

//
// Credential MetaData
//
typealias MsoDocType = String
typealias MsoNameSpace = String

const val MSO_MDOC_FORMAT_VALUE = "mso_mdoc"
val MSO_MDOC_FORMAT = Format(MSO_MDOC_FORMAT_VALUE)

fun ClaimPath.isMsoMDoc(): Boolean = 2 == size && all { it is ClaimPathElement.Claim }

operator fun ClaimPath.Companion.invoke(nameSpace: MsoNameSpace, attributeName: String): ClaimPath =
    claim(nameSpace).claim(attributeName)

fun ClaimDefinition.isMsoMDoc(): Boolean = nested.isEmpty() && path.isMsoMDoc()

operator fun ClaimDefinition.Companion.invoke(
    nameSpace: MsoNameSpace,
    attributeName: String,
    mandatory: Boolean? = null,
    display: Display = emptyMap(),
): ClaimDefinition = ClaimDefinition(ClaimPath(nameSpace, attributeName), mandatory, display)

data class MsoMdocPolicy(val oneTimeUse: Boolean)

/**
 * @param docType string identifying the credential type as defined in ISO.18013-5.
 */
data class MsoMdocCredentialConfiguration(
    override val id: CredentialConfigurationId,
    val docType: MsoDocType,
    override val cryptographicBindingMethodsSupported: Set<CryptographicBindingMethod>,
    val credentialSigningAlgorithmsSupported: NonEmptySet<CoseAlgorithm>?,
    override val scope: Scope,
    override val display: List<CredentialDisplay> = emptyList(),
    val claims: List<ClaimDefinition> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    val policy: MsoMdocPolicy? = null,
) : CredentialConfiguration {
    init {
        require(claims.all { it.isMsoMDoc() }) {
            "'claims' does not contain valid MSO MDoc ClaimDefinitions"
        }
        validateCryptographicBindingsAndProofTypes()
    }
}

internal fun MsoMdocCredentialConfiguration.credentialRequest(
    unvalidatedProofs: NonEmptyList<UnvalidatedProof>,
    credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
): MsoMdocCredentialRequest = MsoMdocCredentialRequest(
    unvalidatedProofs = unvalidatedProofs,
    credentialResponseEncryption = credentialResponseEncryption,
    docType = docType,
)

//
// Credential Request
//
data class MsoMdocCredentialRequest(
    override val unvalidatedProofs: NonEmptyList<UnvalidatedProof>,
    override val credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
    val docType: MsoDocType,
) : CredentialRequest {
    override val format: Format = MSO_MDOC_FORMAT
}

internal fun Raise<String>.validate(msoMdocCredentialRequest: MsoMdocCredentialRequest, meta: MsoMdocCredentialConfiguration) {
    ensure(msoMdocCredentialRequest.docType == meta.docType) {
        "doctype is ${msoMdocCredentialRequest.docType} but was expecting ${meta.docType}"
    }
}
