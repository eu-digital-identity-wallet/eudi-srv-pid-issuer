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
package eu.europa.ec.eudi.pidissuer.adapter.out.learningcredential

import arrow.core.Either
import arrow.core.raise.catch
import arrow.core.raise.either
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.sdJwtVcIssuer
import eu.europa.ec.eudi.pidissuer.domain.Format
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.uuid.Uuid

interface EncodeLearningCredential {

    val format: Format
    val type: String

    suspend operator fun invoke(
        learningCredential: LearningCredential,
        holderKey: JWK,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError, JsonElement>

    companion object {
        fun sdJwtVcCompact(
            digestsHashAlgorithm: HashAlgorithm,
            issuerSigningKey: IssuerSigningKey,
            vct: SdJwtVcType,
        ): EncodeLearningCredential = EncodeLearningCredentialInSdJwtVcCompact(
            digestsHashAlgorithm,
            issuerSigningKey,
            vct,
        )
    }
}

private class EncodeLearningCredentialInSdJwtVcCompact(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val vct: SdJwtVcType,
) : EncodeLearningCredential {
    override val format: Format = SD_JWT_VC_FORMAT
    override val type: String = vct.value

    private val issuer: SdJwtIssuer<SignedJWT> by lazy { issuerSigningKey.sdJwtVcIssuer(digestsHashAlgorithm) }

    override suspend fun invoke(
        learningCredential: LearningCredential,
        holderKey: JWK,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError, JsonElement> = either {
        val formatter: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE

        val spec = sdJwt {
            claim(RFC7519.JWT_ID, Uuid.random().toHexDashString())
            claim(RFC7519.ISSUED_AT, issuedAt.epochSeconds)
            claim(RFC7519.EXPIRATION_TIME, expiresAt.epochSeconds)
            claim(SdJwtVcSpec.VCT, vct.value)
            cnf(holderKey.toPublicJWK())
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

        val sdJwt = catch({
            issuer.issue(spec).getOrThrow()
        }) { raise(IssueCredentialError.Unexpected("Unable to issue SD-JWT VC Learning Credential", it)) }

        with(NimbusSdJwtOps) {
            JsonPrimitive(sdJwt.serialize())
        }
    }
}

private val Language.value: String
    get() = when (this) {
        Language.EN -> "en"
        Language.JP -> "jp"
    }

private val LevelOfLearningExperience.value: Int
    get() = when (this) {
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
    get() = when (this) {
        IntegrationStackabilityOptions.Yes -> true
        IntegrationStackabilityOptions.No -> false
    }
