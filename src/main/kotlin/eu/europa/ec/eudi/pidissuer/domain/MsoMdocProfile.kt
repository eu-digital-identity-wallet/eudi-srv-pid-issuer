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
import kotlin.time.Duration

//
// Credential MetaData
//
typealias MsoDocType = String
typealias MsoNameSpace = String

const val MSO_MDOC_FORMAT_VALUE = "mso_mdoc"
val MSO_MDOC_FORMAT = Format(MSO_MDOC_FORMAT_VALUE)

fun ClaimPath.isMsoMDoc(): Boolean = 2 == size && all { it is ClaimPathElement.Claim }

operator fun ClaimPath.Companion.invoke(
    nameSpace: MsoNameSpace,
    attributeName: String,
): ClaimPath = claim(nameSpace).claim(attributeName)

fun ClaimDefinition.isMsoMDoc(): Boolean = nested.isEmpty() && path.isMsoMDoc()

operator fun ClaimDefinition.Companion.invoke(
    nameSpace: MsoNameSpace,
    attributeName: String,
    mandatory: Boolean? = null,
    display: Display = emptyMap(),
): ClaimDefinition = ClaimDefinition(ClaimPath(nameSpace, attributeName), mandatory, display)

/**
 * @param docType string identifying the credential type as defined in ISO.18013-5.
 */
data class MsoMdocCredentialConfiguration(
    override val id: CredentialConfigurationId,
    override val scope: Scope,
    override val display: List<CredentialDisplay> = emptyList(),
    override val deviceBinding: DeviceBinding.Required,
    override val attestationCategory: AttestationCategory,
    override val credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    override val validity: Duration,
    val docType: MsoDocType,
    val credentialSigningAlgorithmsSupported: NonEmptySet<CoseAlgorithm>?,
    val claims: List<ClaimDefinition> = emptyList(),
) : CredentialConfiguration {
    init {
        require(claims.all { it.isMsoMDoc() }) {
            "'claims' does not contain valid MSO MDoc ClaimDefinitions"
        }
        require(validity.isPositive()) { "'validity' must be a positive duration" }
    }

    override val cryptographicBindingMethodsSupported: NonEmptySet<CryptographicBindingMethod>
        get() = nonEmptySetOf(CryptographicBindingMethod.CoseKey)
}
