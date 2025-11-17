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
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.IsoAlpha2CountryCode
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import kotlin.time.Instant

@JvmInline
value class NonBlankString(val value: String) {
    init {
        require(value.isNotBlank())
    }

    override fun toString(): String = value
}

data class Issuer(
    val name: Name,
    val country: IsoAlpha2CountryCode,
    val uri: HttpsUrl? = null,
) {
    typealias Name = NonBlankString
}

typealias FamilyName = NonBlankString
typealias GivenName = NonBlankString
typealias AchievementTitle = NonBlankString
typealias AchievementDescription = NonBlankString

typealias LearningOutcome = NonBlankString
typealias AssessmentGrade = NonBlankString

data class LearningCredential(
    val issuer: Issuer,
    val dateOfIssuance: Instant,
    val dateOfExpiry: Instant? = null,
    val familyName: FamilyName,
    val givenName: GivenName,
    val achievementTitle: AchievementTitle,
    val achievementDescription: AchievementDescription? = null,
    val learningOutcomes: NonEmptyList<LearningOutcome>? = null,
    val assessmentGrade: AssessmentGrade? = null,
) {
    companion object
}
