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
package eu.europa.ec.eudi.pidissuer.adapter.out.simplecredential

import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import java.util.*

object SdJwtVcClaims {
    val FamilyName: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("family_name"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Family Name",
        ),
    )
    val GivenName: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("given_name"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Given Name",
        ),
    )
    val Email: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("email"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Email Address",
        ),
    )
    val DateOfBirth: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("date_of_birth"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Date of Birth",
        ),
    )

    fun all(): NonEmptyList<ClaimDefinition> = nonEmptyListOf(
        FamilyName,
        GivenName,
        Email,
        DateOfBirth,
    )
}

fun SimpleCredential.Companion.sdJwtVcCredentialConfiguration(
    id: CredentialConfigurationId,
    scope: Scope,
    credentialSigningAlgorithm: JWSAlgorithm,
    display: CredentialDisplay,
    proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    keyAttestationRequirement: KeyAttestationRequirement,
) = SdJwtVcCredentialConfiguration(
    id,
    SdJwtVcType("urn:eu.europa.ec.eudi:simple:credential:1"),
    scope,
    nonEmptySetOf(CryptographicBindingMethod.Jwk),
    nonEmptySetOf(credentialSigningAlgorithm),
    nonEmptyListOf(display),
    SdJwtVcClaims.all(),
    ProofTypesSupported(
        ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement),
    ),
    attestationCategory = AttestationCategory.Eaa,
)
