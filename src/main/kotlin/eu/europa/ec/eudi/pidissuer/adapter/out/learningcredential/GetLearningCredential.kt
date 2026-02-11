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

import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.IsoAlpha2CountryCode
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import kotlin.random.Random
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

fun interface GetLearningCredential {
    suspend operator fun invoke(context: AuthorizationContext): LearningCredential

    companion object {
        fun mock(clock: Clock, getPidData: GetPidData): GetLearningCredential = GetMockLearningCredential(clock, getPidData)
    }
}

private class GetMockLearningCredential(
    private val clock: Clock,
    private val getPidData: GetPidData,
    private val random: Random = Random,
) : GetLearningCredential {
    override suspend fun invoke(context: AuthorizationContext): LearningCredential {
        val now = clock.now()
        val pid = checkNotNull(getPidData(context.username)?.first)
        return LearningCredential(
            issuer = Issuer(
                name = Issuer.Name("Technical University of Munich: Department of Applied Sciences"),
                country = IsoAlpha2CountryCode("DE"),
                uri = HttpsUrl.unsafe("https://university.de/department-of-applied-sciences"),
            ),
            dateOfIssuance = run {
                val twoYearsAgo = now - (2 * 365).days
                Instant.fromEpochSeconds(random.nextLong(twoYearsAgo.epochSeconds, now.epochSeconds))
            },
            dateOfExpiry =
                run {
                    val inTwoYears = now + (2 * 365).days
                    val inFifteenYears = now + (15 * 365).days
                    Instant.fromEpochSeconds(random.nextLong(inTwoYears.epochSeconds, inFifteenYears.epochSeconds))
                },
            familyName = FamilyName(pid.familyName.value),
            givenName = GivenName(pid.givenName.value),
            achievementTitle = AchievementTitle("Foundations of Applied AI in Business"),
            achievementDescription =
                AchievementDescription(
                    "A comprehensive introductory course on the practical application of " +
                        "Artificial Intelligence models to solve common business problems.",
                ),
            learningOutcomes =
                nonEmptyListOf(
                    LearningOutcome("Analyze business processes to identify opportunities for AI implementation"),
                    LearningOutcome("Evaluate the suitability of different machine learning models for a given problem"),
                ),
            assessmentGrade = AssessmentGrade("Excellent"),
            languagesOfClasses = nonEmptyListOf(Language.entries.shuffled(random).first()),
            learnerIdentification = LearnerIdentification("0123456"),
            expectedStudyTime = ExpectedStudyTime("12 months"),
            levelOfLearningExperience = LevelOfLearningExperience.entries.shuffled(random).first(),
            typesOfQualityAssurance = nonEmptyListOf(TypesOfQualityAssurance("Institutional Evaluation")),
            prerequisitesToEnroll = nonEmptyListOf(PrerequisiteToEnroll("Familiarity with Python")),
            integrationStackabilityOptions = IntegrationStackabilityOptions.entries.shuffled(random).first(),
        )
    }
}
