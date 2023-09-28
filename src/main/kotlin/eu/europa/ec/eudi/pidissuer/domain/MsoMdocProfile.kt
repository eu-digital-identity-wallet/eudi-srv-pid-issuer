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

import com.nimbusds.jose.JWSAlgorithm

typealias MsoDocType = String
typealias MsoNameSpace = String
data class MsoMdocAttribute<out V>(val name: String, val value: V)
private const val MSO_MDOC_FORMAT = "mso_mdoc"
data class MsoAttribute(val name: String, val display: Display = emptyMap())
typealias MsoClaims = Map<MsoNameSpace, List<MsoAttribute>>

/**
 * @param docType string identifying the credential type as defined in ISO.18013-5.
 */
data class MsoMdocMetaData(
    val docType: String,
    val cryptographicSuitesSupported: List<JWSAlgorithm>,
    override val scope: Scope? = null,
    override val display: List<CredentialDisplay> = emptyList(),
    val msoClaims: MsoClaims = emptyMap(),
) : CredentialMetaData {
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
        get() = listOf(CryptographicBindingMethod.Mso(cryptographicSuitesSupported))

    override val format: Format = Format(MSO_MDOC_FORMAT)
}

data class MsoMdoc(
    val docType: MsoDocType,
    val attributes: Map<MsoNameSpace, MsoMdocAttribute<Any>>,
)
