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
package eu.europa.ec.eudi.pidissuer.adapter.out.oauth

import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.ClaimPath
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.*

interface IsAttribute {
    val attribute: ClaimDefinition
}

//
// Open ID Connect Core
//

val OidcSub: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("sub"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Subject - Identifier for the End-User at the Issuer"),
    )
}

val OidcFamilyName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("family_name"),
        display = mapOf(Locale.ENGLISH to "Current last name(s) or surname(s) of the PID User."),
    )
}

val OidcGivenName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("given_name"),
        display = mapOf(Locale.ENGLISH to "Current first name(s), including middle name(s), of the PID User."),
    )
}

val OidcBirthDate: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("birthdate"),
        display = mapOf(Locale.ENGLISH to "Day, month, and year on which the PID User was born."),
    )
}

val OidcGender: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("gender"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "PID User’s gender, using a value as defined in OpenID Connect Core 1.0."),
    )
}

// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
@Serializable
data class OidcAddressClaim(
    @SerialName("street_address") val streetAddress: String? = null,
    @SerialName("locality") val locality: String? = null,
    @SerialName("region") val region: String? = null,
    @SerialName("postal_code") val postalCode: String? = null,
    @SerialName("country") val country: String? = null,
    @SerialName("formatted") val formatted: String? = null,
    @SerialName("house_number") val houseNumber: String? = null,
) {

    companion object : IsAttribute {
        const val NAME = "address"

        override val attribute: ClaimDefinition
            get() = ClaimDefinition(
                path = ClaimPath.claim(NAME),
                mandatory = false,
                display = mapOf(
                    Locale.ENGLISH to "The full address of the place where the PID User currently resides and/or " +
                        "can be contacted (street name, house number, city etc.).",
                ),
                nested = listOf(Street, Locality, Region, PostalCode, Country, Formatted, HouseNumber),
            )

        val Street = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("street_address"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The name of the street where the user to whom the person identification " +
                    "data relates currently resides.",
            ),
        )
        val Locality = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("locality"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The municipality, city, town, or village where the user to whom the " +
                    "person identification data relates currently resides.",
            ),
        )
        val Region = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("region"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The state, province, district, or local area where the user to " +
                    "whom the person identification data relates currently resides.",
            ),
        )
        val PostalCode = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("postal_code"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The postal code of the place where the user to whom the person identification " +
                    "data relates currently resides.",
            ),
        )
        val Country = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("country"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The country where the user to whom the person identification data " +
                    "relates currently resides, as an alpha-2 country code as specified in ISO 3166-1.",
            ),
        )
        val HouseNumber = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("house_number"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The house number where the user to whom the person identification data " +
                    "relates currently resides, including any affix or suffix.",
            ),
        )
        val Formatted = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("formatted"),
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "The full address of the place where the user to whom the person " +
                    "identification data relates currently resides or can be contacted (street name, " +
                    "house number, city etc.).",
            ),
        )
    }
}

//
// Open ID Connect Identity Assurance
// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-4

val OidcAssuranceNationalities: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("nationalities"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Alpha-2 country code as specified in ISO 3166-1, representing the nationality of the PID User."),
    )
}

val OidcAssuranceBirthFamilyName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("birth_family_name"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
    )
}
val OidcAssuranceBirthGivenName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("birth_given_name"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
    )
}

@Serializable
data class OidcAssurancePlaceOfBirth(
    val locality: String? = null,
    val region: String? = null,
    val country: String? = null,
) {
    companion object : IsAttribute {
        const val NAME = "place_of_birth"

        override val attribute: ClaimDefinition
            get() = ClaimDefinition(
                path = ClaimPath.claim(NAME),
                mandatory = false,
                display = mapOf(Locale.ENGLISH to "The country, state, and city where the PID User was born."),
                nested = listOf(Locality, Region, Country),
            )

        val Locality = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("locality"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "The city where the PID User was born."),
        )

        val Region = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("region"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "The state where the PID User was born."),
        )

        val Country = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("country"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "The country where the PID User was born."),
        )
    }
}
