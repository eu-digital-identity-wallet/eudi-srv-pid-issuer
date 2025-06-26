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
package eu.europa.ec.eudi.pidissuer.adapter.out.ehic

import java.time.Clock
import java.time.ZonedDateTime
import java.util.UUID
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration

class GetEuropeanHealthInsuranceCardDataMock(
    private val clock: Clock,
    private val issuingCountry: IssuingCountry,
) : GetEuropeanHealthInsuranceCardData {

    override suspend fun invoke(): EuropeanHealthInsuranceCard {
        val now = ZonedDateTime.now(clock)
        val endingDate = now + 365.days.toJavaDuration()
        val startingDate = endingDate - (5 * 31).days.toJavaDuration()

        return EuropeanHealthInsuranceCard(
            personalAdministrativeNumber = PersonalAdministrativeNumber(UUID.randomUUID().toString()),
            issuingAuthority = IssuingAuthority(
                id = IssuingAuthority.Id("Uber-GR"),
                name = Name("Uber Health Insurance"),
            ),
            issuingCountry = issuingCountry,
            authenticSource = AuthenticSource(
                id = AuthenticSource.Id("Uber-GR"),
                name = Name("Uber Health Insurance"),
            ),
            endingDate = endingDate,
            startingDate = startingDate,
            documentNumber = DocumentNumber(UUID.randomUUID().toString()),
        )
    }
}
