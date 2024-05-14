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
package eu.europa.ec.eudi.pidissuer.adapter.out.diploma

import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.IsAttribute
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.Locale.ENGLISH

data class Diploma(
    val name: String,
    val achieved: AchievedClaim,
    val entitledTo: EntitledToClaim? = null,
    val performedClaim: PerformedClaim? = null,
)

@Serializable
data class AchievedClaim(
    val learningAchievements: List<LearningAchievement>,
) {
    companion object : IsAttribute {
        const val NAME = "achieved"
        override val attribute: AttributeDetails
            get() = AttributeDetails(
                name = NAME,
                mandatory = false,
                display = mapOf(
                    ENGLISH to "An achievement of the person.",
                ),
            )
    }
}

@Serializable
data class EntitledToClaim(
    val entitlements: List<Entitlement>,
) {
    companion object : IsAttribute {
        const val NAME = "entitledTo"
        override val attribute: AttributeDetails
            get() = AttributeDetails(
                name = NAME,
                mandatory = false,
                display = mapOf(
                    ENGLISH to "The entitlement of the person.",
                ),
            )
    }
}

@Serializable
data class PerformedClaim(
    val learningActivities: List<LearningActivity>,
) {
    companion object : IsAttribute {
        const val NAME = "performed"
        override val attribute: AttributeDetails
            get() = AttributeDetails(
                name = NAME,
                mandatory = false,
                display = mapOf(
                    ENGLISH to "A learning activity that a person participated in or attended.",
                ),
            )
    }
}

/**
 * The acquisition of knowledge, skills or responsibility and autonomy. A recognised and/or awarded set of learning outcomes of an individual.
 */
@Serializable
data class LearningAchievement(
    @SerialName("id") val id: String,
    @SerialName("title") val title: String,
    @SerialName("definition") val definition: String,
)

/**
 * Defines a right, e.g. to practice a profession, take advantage of a learning opportunity or join an organisation,
 * as a result of the acquisition of knowledge, skills, responsibility and/or autonomy
 */
@Serializable
data class Entitlement(
    @SerialName("id") val id: String,
    @SerialName("title") val title: String,
    @SerialName("definition") val definition: String,
    @SerialName("issuedDate") val issuedAt: Instant? = null,
    @SerialName("expiryDate") val expiresOn: Instant? = null,
)

/**
 * Defines any process which leads to the acquisition of knowledge, skills or responsibility and autonomy.
 */
@Serializable
data class LearningActivity(
    @SerialName("id") val id: String,
    @SerialName("definition") val definition: String,
    @SerialName("startedAtTime") val started: Instant,
    @SerialName("endedAtTime") val ended: Instant,
)

interface GenerateUserDiplomaData {

    operator fun invoke(): Diploma
}
