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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.learningcredential

import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.sdjwtvc.AttestedClaims
import eu.europa.ec.eudi.pidissuer.adapter.out.sdjwtvc.EncodeAttributesInSdJwtVc
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.sdjwt.*
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.time.toJavaInstant

fun encodeLearningCredentialInSdJwtVc(
    option: EncodeAttributesInSdJwtVc.Option = EncodeAttributesInSdJwtVc.Option.Compact,
    digestsHashAlgorithm: HashAlgorithm = HashAlgorithm.SHA_256,
    issuerSigningKey: IssuerSigningKey,
    vct: SdJwtVcType,
): EncodeAttributesInSdJwtVc<AttestedClaims<LearningCredential>> =
    EncodeAttributesInSdJwtVc(option, digestsHashAlgorithm, issuerSigningKey, vct) { learningCredential ->
        val formatter: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE
        claim(SdJwtVcSpec.VCT, vct.value)
        with(learningCredential) {
            with(issuer) {
                claim(SdJwtVcClaims.IssuingAuthority.name, name.value)
                claim(SdJwtVcClaims.IssuingCountry.name, country.code)
                claim(RFC7519.ISSUER, uri.externalForm)
            }
            claim(
                SdJwtVcClaims.DateOfIssuance.name,
                formatter.format(ZonedDateTime.ofInstant(dateOfIssuance.toJavaInstant(), ZoneOffset.UTC)),
            )
            if (null != dateOfExpiry) {
                claim(
                    SdJwtVcClaims.DateOfExpiry.name,
                    formatter.format(ZonedDateTime.ofInstant(dateOfExpiry.toJavaInstant(), ZoneOffset.UTC)),
                )
            }
            sdClaim(SdJwtVcClaims.FamilyName.name, familyName.value)
            if (null != givenName) {
                sdClaim(SdJwtVcClaims.GivenName.name, givenName.value)
            }
            claim(SdJwtVcClaims.AchievementTitle.name, achievementTitle.value)
            if (null != achievementDescription) {
                claim(SdJwtVcClaims.AchievementDescription.name, achievementDescription.value)
            }
            if (null != learningOutcomes) {
                sdArrClaim(SdJwtVcClaims.LearningOutcomes.name) {
                    learningOutcomes.forEach { learningOutcome -> claim(learningOutcome.value) }
                }
            }
            if (null != assessmentGrade) {
                sdClaim(SdJwtVcClaims.AssessmentGrade.name, assessmentGrade.value)
            }
            arrClaim(SdJwtVcClaims.LanguageOfClasses.name) {
                languagesOfClasses.forEach { languageOfClasses -> claim(languageOfClasses.value) }
            }
            sdClaim(SdJwtVcClaims.LearnerIdentification.name, learnerIdentification.value)
            sdClaim(SdJwtVcClaims.ExpectedStudyTime.name, expectedStudyTime.value)
            sdClaim(SdJwtVcClaims.LevelOfLearningExperience.name, levelOfLearningExperience.value)
            sdArrClaim(SdJwtVcClaims.TypesOfQualityAssurance.name) {
                typesOfQualityAssurance.forEach { typeOfQualityAssurance -> claim(typeOfQualityAssurance.value) }
            }
            if (null != prerequisitesToEnroll) {
                sdArrClaim(SdJwtVcClaims.PrerequisitesToEnroll.name) {
                    prerequisitesToEnroll.forEach { prerequisiteToEnroll -> claim(prerequisiteToEnroll.value) }
                }
            }
            if (null != integrationStackabilityOptions) {
                sdClaim(SdJwtVcClaims.IntegrationStackabilityOptions.name, integrationStackabilityOptions.value)
            }
        }
    }

private val Language.value: String
    get() =
        when (this) {
            Language.EN -> "en"
            Language.JP -> "jp"
        }

private val LevelOfLearningExperience.value: Int
    get() =
        when (this) {
            LevelOfLearningExperience.Level1 -> 1
            LevelOfLearningExperience.Level2 -> 2
            LevelOfLearningExperience.Level3 -> 3
            LevelOfLearningExperience.Level4 -> 4
            LevelOfLearningExperience.Level5 -> 5
            LevelOfLearningExperience.Level6 -> 6
            LevelOfLearningExperience.Level7 -> 7
            LevelOfLearningExperience.Level8 -> 8
        }

private val IntegrationStackabilityOptions.value: Boolean
    get() =
        when (this) {
            IntegrationStackabilityOptions.Yes -> true
            IntegrationStackabilityOptions.No -> false
        }
