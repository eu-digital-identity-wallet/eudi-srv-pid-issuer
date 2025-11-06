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
package eu.europa.ec.eudi.pidissuer.adapter.out.learningcredential

import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import java.util.*

object SdJwtVcClaims {
    val DateOfIssuance: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("date_of_issuance"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Date of Issuance",
        ),
    )
    val DateOfExpiry: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("date_of_issuance"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Date of Expiry",
        ),
    )
    val FamilyName: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("family_name"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Family Name(s)",
        ),
    )
    val GivenName: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("given_name"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Given Name(s)",
        ),
    )
    val AchievementTitle: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("achievement_title"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Achievement Title",
        ),
    )
    val AchievementDescription: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("achievement_description"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Achievement Description",
        ),
    )
    val CreditFramework: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("credit_received_framework"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Credit Framework",
        ),
    )
    val CreditPoints: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("credit_received_points"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Credit Points",
        ),
    )
    val LearningOutcomes = ClaimDefinition(
        path = ClaimPath.claim("learning_outcomes"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Learning Outcomes",
        ),
    )
    val AssessmentGrade: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("assessment_grade"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Assessment Grade",
        ),
    )

    fun all(): NonEmptyList<ClaimDefinition> = nonEmptyListOf(
        DateOfIssuance,
        DateOfExpiry,
        FamilyName,
        GivenName,
        AchievementTitle,
        AchievementDescription,
        CreditFramework,
        CreditPoints,
        LearningOutcomes,
        AssessmentGrade,
    )
}

fun LearningCredential.Companion.sdJwtVcCredentialConfiguration(
    id: CredentialConfigurationId,
    scope: Scope,
    credentialSigningAlgorithm: JWSAlgorithm,
    display: CredentialDisplay,
    proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    keyAttestationRequirement: KeyAttestationRequirement,
) = SdJwtVcCredentialConfiguration(
    id,
    SdJwtVcType("urn:eu.europa.ec.eudi:learning:credential:1"),
    scope,
    nonEmptySetOf(CryptographicBindingMethod.Jwk),
    nonEmptySetOf(credentialSigningAlgorithm),
    nonEmptyListOf(display),
    SdJwtVcClaims.all(),
    ProofTypesSupported(
        ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement),
    ),
)
