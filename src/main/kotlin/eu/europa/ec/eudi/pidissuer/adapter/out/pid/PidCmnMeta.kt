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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import eu.europa.ec.eudi.pidissuer.domain.*
import java.util.*

internal const val PID_DOCTYPE = "eu.europa.ec.eudiw.pid"

internal fun pidDocType(v: Int?): String =
    if (v == null) PID_DOCTYPE
    else "$PID_DOCTYPE.$v"

val pidDisplay = listOf(
    CredentialDisplay(
        name = DisplayName("PID", Locale.ENGLISH),
        logo = ImageUrl(
            url = HttpsUrl.of("https://examplestate.com/public/mdl.png")!!,
            alternativeText = "A square figure of a PID",
        ),
    ),
)

//
// Meta
//

val pidAttributes = listOf(

    AttributeDetails(
        name = "family_name",
        display = mapOf(Locale.ENGLISH to "Current Family Name"),
    ),
    AttributeDetails(
        name = "given_name",
        display = mapOf(Locale.ENGLISH to "Current First Names"),
    ),
    AttributeDetails(
        name = "birth_date",
        display = mapOf(Locale.ENGLISH to "Date of Birth"),
    ),
    AttributeDetails(
        name = "age_over_18",
        display = mapOf(Locale.ENGLISH to "Adult or minor"),
    ),
    AttributeDetails(
        name = "age_birth_year",
    ),
    AttributeDetails(
        name = "unique_id",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Unique Identifier"),
    ),
    AttributeDetails(name = "family_name_birth"),
    AttributeDetails(name = "given_name_birth"),
    AttributeDetails(name = "birth_place"),
    AttributeDetails(name = "birth_country"),
    AttributeDetails(name = "birth_state"),
    AttributeDetails(name = "birth_city"),
    AttributeDetails(name = "resident_country"),
    AttributeDetails(name = "resident_state"),
    AttributeDetails(name = "resident_city"),
    AttributeDetails(name = "resident_postal_ode"),
    AttributeDetails(name = "resident_house_number"),
    AttributeDetails(name = "gender"),
    AttributeDetails(name = "nationality"),
)
