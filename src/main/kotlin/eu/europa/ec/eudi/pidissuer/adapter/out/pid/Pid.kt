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

import java.time.LocalDate
import java.time.LocalDateTime
import java.time.Year

@JvmInline
value class FamilyName(val value: String)

@JvmInline
value class GivenName(val value: String)

/**
 * An Alpha-2 country
 * code as specified in ISO 3166-1.
 */
@JvmInline
value class IsoCountry(val value: String)

@JvmInline
value class Street(val value: String)

@JvmInline
value class State(val value: String)

@JvmInline
value class City(val value: String)

@JvmInline
value class PostalCode(val value: String)

typealias Address = String

/**
 * Gender, using a value as defined in ISO/IEC 5218.
 */
@JvmInline
value class IsoGender(val value: UInt)

/**
 * Gender, using a value as defined in OpenID Connect Core 1.0.
 */
@JvmInline
value class OidcGender private constructor(val value: String) {
    companion object {
        val Male: OidcGender = OidcGender("male")
        val Female: OidcGender = OidcGender("female")

        operator fun invoke(value: String): OidcGender =
            when (value) {
                "male" -> Male
                "female" -> Female
                else -> OidcGender(value)
            }
    }
}

typealias Nationality = IsoCountry

/**
 * @param familyName Current last name(s) or surname(s) of the PID User.
 * @param givenName Current first name(s), including middle name(s), of the PID User.
 * @param birthDate Day, month, and year on which the PID User was born.
 * If unknown, approximate date of birth.
 * @param ageOver18 Attesting whether the PID User is currently an adult (true) or a
 * minor (false).
 * @param ageBirthYear The year when the PID User was born. If unknown, approximate
 * year.
 * @param ageInYears The current age of the PID User in years.
 * @param familyNameBirth First name(s), including middle name(s), of the PID User at the
 * time of birth.
 * @param givenNameBirth First name(s), including middle name(s), of the PID User at the time of birth.
 * @param birthPlace The country, state, and city where the PID User was born.
 * @param birthCountry The country where the PID User was born, as an Alpha-2 country
 * code as specified in ISO 3166-1
 * @param birthState The state, province, district, or local area where the PID User was
 * born.
 * @param birthCity The municipality, city, town, or village where the PID User was born
 * @param residentAddress The full address of the place where the PID User currently resides and/or can be
 * contacted (street name, house number, city etc.).
 * @param residentCountry The country where the PID User currently resides, as an Alpha-2
 * country code as specified in ISO 3166-1.
 * @param residentState The state, province, district, or local area where the PID User
 * currently resides.
 * @param residentCity The municipality, city, town, or village where the PID User
 * currently resides.
 *This document stipulates that a
 */
data class Pid(
    val familyName: FamilyName,
    val givenName: GivenName,
    val birthDate: LocalDate,
    val ageOver18: Boolean? = null,
    val ageBirthYear: Year? = null,
    val ageInYears: UInt? = null,
    val familyNameBirth: FamilyName? = null,
    val givenNameBirth: GivenName? = null,
    val birthPlace: String? = null,
    val birthCountry: IsoCountry? = null,
    val birthState: State? = null,
    val birthCity: City? = null,
    val residentAddress: Address? = null,
    val residentStreet: Street? = null,
    val residentCountry: IsoCountry? = null,
    val residentState: State? = null,
    val residentCity: City? = null,
    val residentPostalCode: PostalCode? = null,
    val residentHouseNumber: String? = null,
    val gender: IsoGender? = null,
    val nationality: Nationality? = null,
) {
    init {
        ageBirthYear?.let { year ->
            require(birthDate.year == year.value) {
                "Given ageBirthYear = ${year.value} is not equal to year of birthDate $birthDate"
            }
        }
    }
}

/**
 * Name of the administrative authority that has issued this PID instance,
 * or the ISO 3166 Alpha-2 country code of the respective Member State
 * if there is no separate authority authorized to issue PID
 */
sealed interface IssuingAuthority {
    @JvmInline
    value class MemberState(val code: IsoCountry) : IssuingAuthority

    @JvmInline
    value class AdministrativeAuthority(val value: String) : IssuingAuthority

    fun valueAsString(): String = when (this) {
        is AdministrativeAuthority -> value
        is MemberState -> code.value
    }
}

@JvmInline
value class DocumentNumber(val value: String)

@JvmInline
value class AdministrativeNumber(val value: String)

sealed interface PortraitImage {
    @JvmInline
    value class JPEG(val value: ByteArray) : PortraitImage

    @JvmInline
    value class JPEG2000(val value: ByteArray) : PortraitImage
}

data class Portrait(val image: PortraitImage, val captureDate: LocalDateTime)

/**
 * Country subdivision code of the jurisdiction that issued the PID, as defined in ISO 3166-2:2020, Clause 8.
 * The first part of the code SHALL be the same as the value for issuing_country.
 */
typealias IsoCountrySubdivision = String

/**
 * @param issuanceDate Date (and possibly time) when the PID was issued.
 * @param expiryDate Date (and possibly time) when the PID will expire.
 * @param issuingAuthority Name of the administrative authority that has issued this PID instance,
 * or the ISO 3166 Alpha-2 country code of the respective Member State
 * if there is no separate authority authorized to issue PID
 * @param documentNumber A number for the PID, assigned by the PID Provider
 * @param administrativeNumber A number assigned by the PID Provider for audit control or other purposes.
 * @param issuingCountry Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider’s country or territory.
 * @param issuingJurisdiction Country subdivision code of the jurisdiction that issued the PID, as defined
 * in ISO 3166-2:2020, Clause 8. The first part of the code SHALL be the same as the value for issuing_country.
 */
data class PidMetaData(
    val issuanceDate: LocalDate,
    val expiryDate: LocalDate,
    val issuingAuthority: IssuingAuthority,
    val documentNumber: DocumentNumber? = null,
    val administrativeNumber: AdministrativeNumber? = null,
    val issuingCountry: IsoCountry,
    val issuingJurisdiction: IsoCountrySubdivision? = null,
) {
    init {
        require(issuanceDate.isBefore(expiryDate)) { "Issuance date should be before expiry date" }
        if (issuingAuthority is IssuingAuthority.MemberState) {
            require(issuingAuthority.code == issuingCountry) {
                "IssuanceAuthority ${issuingAuthority.code.value} should be the same with issuingCountry = ${issuingCountry.value}"
            }
        }
    }
}
