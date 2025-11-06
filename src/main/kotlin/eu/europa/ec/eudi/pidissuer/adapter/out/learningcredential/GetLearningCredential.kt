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

import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.domain.Clock
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
) : GetLearningCredential {
    override suspend fun invoke(context: AuthorizationContext): LearningCredential {
        val now = clock.now()
        val pid = checkNotNull(getPidData(context.username)?.first)
        return LearningCredential(
            dateOfIssuance = run {
                val twoYearsAgo = now - (2 * 365).days
                Instant.fromEpochSeconds(Random.nextLong(twoYearsAgo.epochSeconds, now.epochSeconds))
            },
            dateOfExpiry =
                if (Random.nextBoolean()) {
                    val inTwoYears = now + (2 * 365).days
                    val inFifteenYears = now + (15 * 365).days
                    Instant.fromEpochSeconds(Random.nextLong(inTwoYears.epochSeconds, inFifteenYears.epochSeconds))
                } else null,
            familyName = FamilyName(pid.familyName.value),
            givenName = GivenName(pid.givenName.value),
            achievementTitle = AchievementTitle("Foundations of Applied AI in Business"),
            achievementDescription =
                if (Random.nextBoolean()) AchievementDescription(
                    "A comprehensive introductory course on the practical application of " +
                        "Artificial Intelligence models to solve common business problems.",
                )
                else null,
            credits =
                if (Random.nextBoolean()) Credits(framework = Credits.Framework("ECTS"), points = Credits.Points("5"))
                else null,
            learningOutcomes =
                if (Random.nextBoolean())
                    nonEmptyListOf(
                        LearningOutcome("Analyze business processes to identify opportunities for AI implementation"),
                        LearningOutcome("Evaluate the suitability of different machine learning models for a given problem"),
                    )
                else null,
            assessmentGrade =
                if (Random.nextBoolean()) AssessmentGrade("Excellent")
                else null,
        )
    }
}
