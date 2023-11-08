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
import java.util.Locale.ENGLISH

internal const val PID_DOCTYPE = "eu.europa.ec.eudiw.pid"

internal fun pidDocType(v: Int?): String =
    if (v == null) PID_DOCTYPE
    else "$PID_DOCTYPE.$v"

val pidDisplay = listOf(
    CredentialDisplay(
        name = DisplayName("PID", ENGLISH),
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
        display = mapOf(ENGLISH to "Current Family Name"),
    ),
    AttributeDetails(
        name = "given_name",
        display = mapOf(ENGLISH to "Current First Names"),
    ),
    AttributeDetails(
        name = "birth_date",
        display = mapOf(ENGLISH to "Date of Birth"),
    ),
    AttributeDetails(
        name = "age_over_18",
        display = mapOf(ENGLISH to "Adult or minor"),
    ),
    AttributeDetails(
        name = "age_birth_year",
    ),
    AttributeDetails(
        name = "unique_id",
        mandatory = true,
        display = mapOf(ENGLISH to "Unique Identifier"),
    ),
    AttributeDetails(
        name = "family_name_birth",
        mandatory = false,
        display = mapOf(ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
    ),
    AttributeDetails(
        name = "given_name_birth",
        mandatory = false,
        display = mapOf(ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
    ),
    AttributeDetails(
        name = "birth_place",
        mandatory = false,
        display = mapOf(ENGLISH to "The country, state, and city where the PID User was born."),
    ),
    AttributeDetails(
        name = "birth_country",
        mandatory = false,
        display = mapOf(ENGLISH to "The country where the PID User was born, as an Alpha-2 country code as specified in ISO 3166-1."),
    ),
    AttributeDetails(
        name = "birth_state",
        mandatory = false,
        display = mapOf(ENGLISH to "The state, province, district, or local area where the PID User was born. "),
    ),
    AttributeDetails(
        name = "birth_city",
        mandatory = false,
        display = mapOf(ENGLISH to "The municipality, city, town, or village where the PID User was born. "),
    ),
    AttributeDetails(
        name = "resident_country",
        mandatory = false,
        display = mapOf(
            ENGLISH to "he country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1.",
        ),
    ),
    AttributeDetails(
        name = "resident_state",
        mandatory = false,
        display = mapOf(ENGLISH to "The state, province, district, or local area where the PID User currently resides"),
    ),
    AttributeDetails(
        name = "resident_city",
        mandatory = false,
        display = mapOf(ENGLISH to "The municipality, city, town, or village where the PID User currently resides."),
    ),
    AttributeDetails(
        name = "resident_postal_code",
        mandatory = false,
        display = mapOf(ENGLISH to "Postal code of the place where the PID User currently resides."),
    ),
    AttributeDetails(
        name = "resident_street",
        mandatory = false,
        display = mapOf(ENGLISH to "The name of the street where the PID User currently resides"),
    ),
    AttributeDetails(
        name = "resident_house_number",
        mandatory = false,
        display = mapOf(ENGLISH to "The house number where the PID User currently resides, including any affix or suffix."),
    ),
    AttributeDetails(
        name = "gender",
        mandatory = false,
        display = mapOf(ENGLISH to "PID User’s gender, using a value as defined in ISO/IEC 5218."),
    ),
    AttributeDetails(
        name = "nationality",
        mandatory = false,
        display = mapOf(ENGLISH to "Alpha-2 country code as specified in ISO 3166-1, representing the nationality of the PID User."),
    ),
)

private infix fun String.inLocale(local: Locale): Pair<Locale, String> = local to this
private fun String.en() = inLocale(ENGLISH)
