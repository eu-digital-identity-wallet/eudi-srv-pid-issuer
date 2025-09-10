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
@Suppress("unused")
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
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Family Name(s)"),
    )
}

val OidcGivenName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("given_name"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Given Name(s)"),
    )
}

val OidcBirthDate: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("birthdate"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Birth Date"),
    )
}

@Suppress("unused")
val OidcGender: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("gender"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Gender"),
    )
}

// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
@Serializable
data class OidcAddressClaim(
    @SerialName("house_number") val houseNumber: String? = null,
    @SerialName("street_address") val streetAddress: String? = null,
    @SerialName("locality") val locality: String? = null,
    @SerialName("region") val region: String? = null,
    @SerialName("postal_code") val postalCode: String? = null,
    @SerialName("country") val country: String? = null,
    @SerialName("formatted") val formatted: String? = null,
) {

    companion object : IsAttribute {
        const val NAME = "address"

        override val attribute: ClaimDefinition
            get() = ClaimDefinition(
                path = ClaimPath.claim(NAME),
                mandatory = false,
                display = mapOf(Locale.ENGLISH to "Address"),
                nested = listOf(HouseNumber, Street, Locality, Region, PostalCode, Country, Formatted),
            )

        val HouseNumber = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("house_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "House Number"),
        )
        val Street = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("street_address"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Street"),
        )
        val Locality = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("locality"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Locality"),
        )
        val Region = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("region"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Region"),
        )
        val PostalCode = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("postal_code"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Postal Code"),
        )
        val Country = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("country"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Country"),
        )
        val Formatted = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("formatted"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Full Address"),
        )
    }
}

//
// Open ID Connect Identity Assurance
// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-4

val OidcAssuranceNationalities: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("nationalities"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Nationality"),
    )
}

val OidcAssuranceBirthFamilyName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("birth_family_name"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Birth Family Name(s)"),
    )
}
val OidcAssuranceBirthGivenName: ClaimDefinition by lazy {
    ClaimDefinition(
        path = ClaimPath.claim("birth_given_name"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Birth Given Name(s)"),
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
                mandatory = true,
                display = mapOf(Locale.ENGLISH to "Birth Place"),
                nested = listOf(Locality, Region, Country),
            )

        val Locality = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("locality"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Locality"),
        )

        val Region = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("region"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Region"),
        )

        val Country = ClaimDefinition(
            path = ClaimPath.claim(NAME).claim("country"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Country"),
        )
    }
}
