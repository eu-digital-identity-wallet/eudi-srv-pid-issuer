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

import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.*

interface IsAttribute {
    val attribute: AttributeDetails
}

//
// Open ID Connect Core
//

val OidcSub: AttributeDetails by lazy {
    AttributeDetails(
        name = "sub",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Subject - Identifier for the End-User at the Issuer"),
    )
}

val OidcFamilyName: AttributeDetails by lazy {
    AttributeDetails(
        name = "family_name",
        display = mapOf(Locale.ENGLISH to "Current last name(s) or surname(s) of the PID User."),
    )
}

val OidcGivenName: AttributeDetails by lazy {
    AttributeDetails(
        name = "given_name",
        display = mapOf(Locale.ENGLISH to "Current first name(s), including middle name(s), of the PID User."),
    )
}

val OidcBirthDate: AttributeDetails by lazy {
    AttributeDetails(
        name = "birthdate",
        display = mapOf(Locale.ENGLISH to "Day, month, and year on which the PID User was born."),
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
) {

    companion object : IsAttribute {
        const val NAME = "address"
        override val attribute: AttributeDetails
            get() = AttributeDetails(
                name = NAME,
                mandatory = false,
                display = mapOf(
                    Locale.ENGLISH to "The full address of the place where the PID User currently resides and/or " +
                        "can be contacted (street name, house number, city etc.).",
                ),
            )
    }
}

//
// Open ID Connect Identity Assurance
// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-4

val OidcAssuranceNationalities: AttributeDetails by lazy {
    AttributeDetails(
        name = "nationalities",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Alpha-2 country code as specified in ISO 3166-1, representing the nationality of the PID User."),
    )
}

val OidcAssuranceBirthFamilyName: AttributeDetails by lazy {
    AttributeDetails(
        name = "birth_family_name",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
    )
}
val OidcAssuranceBirthGivenName: AttributeDetails by lazy {
    AttributeDetails(
        name = "birth_given_name",
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
        override val attribute: AttributeDetails
            get() = AttributeDetails(
                name = NAME,
                mandatory = false,
                display = mapOf(Locale.ENGLISH to "The country, state, and city where the PID User was born."),
            )
    }
}
