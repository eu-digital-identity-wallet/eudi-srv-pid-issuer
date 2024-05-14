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

import kotlinx.datetime.toKotlinInstant
import java.time.Clock
import kotlin.time.Duration

class UserDiplomaMockData(
    private val clock: Clock,
) : GenerateUserDiplomaData {

    override fun invoke(): Diploma = Diploma(
        name = "ComputerScienceMasterDegree",
        achieved = AchievedClaim(
            listOf(
                LearningAchievement(
                    id = "urn:epass:learningAchievement:1",
                    title = "ComputerScienceMasterDegree",
                    definition = "Master of Science in Computer Science",
                ),
            ),
        ),
        entitledTo = EntitledToClaim(
            listOf(
                Entitlement(
                    id = "urn:epass:entitlement:1",
                    title = "Postgraduate doctoral study",
                    definition = "Competences the student acquires after the completion of Graduate university study are sufficient " +
                        "conditions for attending the programme of Postgraduate doctoral study at the Faculty of Computer Science," +
                        " as well as for attending the same or similar programmes and Postgraduate specialist studies at other " +
                        " faculties of Computer Science in Croatia. The acquired learning outcomes enable the student to attend other" +
                        " postgraduate study programmes in the field of information technology sciences.",
                    issuedAt = clock.instant().toKotlinInstant().minus(Duration.parse("365d")),
                    expiresOn = clock.instant().toKotlinInstant().plus(Duration.parse("365d")),
                ),
            ),
        ),
    )
}
