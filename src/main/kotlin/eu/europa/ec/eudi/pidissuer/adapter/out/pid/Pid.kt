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

import arrow.core.NonEmptyList
import kotlinx.datetime.LocalDate
import java.net.URI
import java.util.regex.Pattern

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

typealias Nationality = IsoCountry

typealias EmailAddress = String

@JvmInline
value class PhoneNumber(val value: String) {
    init {
        require(value.matches(PATTERN.toRegex())) { "not a valid phone number" }
    }

    override fun toString(): String = value

    companion object {
        val PATTERN: Pattern = Pattern.compile("^\\+[1-9][0-9]+$")
    }
}

data class PlaceOfBirth(
    val country: IsoCountry? = null,
    val region: State? = null,
    val locality: City? = null,
)

/**
 * @param familyName Current last name(s) or surname(s) of the PID User.
 * @param givenName Current first name(s), including middle name(s), of the PID User.
 * @param birthDate Day, month, and year on which the PID User was born.
 * If unknown, approximate date of birth.
 * @param birthPlace The country as an alpha-2 country code as specified in ISO 3166-1,
 * or the state, province, district, or local area or the municipality, city, town,
 * or village where the user to whom the PID User was born.
 * @param nationalities One or more alpha-2 country codes as specified in ISO 3166-1,
 * representing the nationality of the user to whom the person identification data relates.
 * @param residentAddress The full address of the place where the PID User currently resides and/or can be
 * contacted (street name, house number, city etc.).
 * @param residentCountry The country where the PID User currently resides, as an Alpha-2
 * country code as specified in ISO 3166-1.
 * @param residentState The state, province, district, or local area where the PID User
 * currently resides.
 * @param residentCity The municipality, city, town, or village where the PID User
 * currently resides.
 * @param residentPostalCode The postal code of the area where the PID User
 * currently resides.
 * @param residentStreet The street name where the PID User currently resides.
 * @param residentHouseNumber The house number where the PID User currently resides.
 * @param portrait Facial image of the PID user compliant with ISO 19794-5 or ISO 39794 specifications.
 * @param familyNameBirth First name(s), including middle name(s), of the PID User at the
 * time of birth.
 * @param givenNameBirth First name(s), including middle name(s), of the PID User at the time of birth.
 * @param sex The gender of the PID User as specified by ISO/IEC 5218
 * @param emailAddress Electronic mail address of the PID User to whom the person identification data relates,
 * in conformance with [RFC 5322].
 * @param mobilePhoneNumber Mobile telephone number of the User to whom the person identification data relates,
 * starting with the '+' symbol as the international code prefix and the country code, followed by numbers only.
 */
data class Pid(
    val familyName: FamilyName,
    val givenName: GivenName,
    val birthDate: LocalDate,
    val birthPlace: PlaceOfBirth? = null,
    val nationalities: NonEmptyList<Nationality>,
    val residentAddress: Address? = null,
    val residentCountry: IsoCountry? = null,
    val residentState: State? = null,
    val residentCity: City? = null,
    val residentPostalCode: PostalCode? = null,
    val residentStreet: Street? = null,
    val residentHouseNumber: String? = null,
    val portrait: PortraitImage? = null,
    val familyNameBirth: FamilyName? = null,
    val givenNameBirth: GivenName? = null,
    val sex: IsoGender? = null,
    val emailAddress: EmailAddress? = null,
    val mobilePhoneNumber: PhoneNumber? = null,
)

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

/**
 * Country subdivision code of the jurisdiction that issued the PID, as defined in ISO 3166-2:2020, Clause 8.
 * The first part of the code SHALL be the same as the value for issuing_country.
 */
typealias IsoCountrySubdivision = String

/**
 * @param personalAdministrativeNumber A number assigned by the PID Provider for audit control or other purposes.
 * @param expiryDate Date (and possibly time) when the PID will expire.
 * @param issuingAuthority Name of the administrative authority that has issued this PID instance,
 * or the ISO 3166 Alpha-2 country code of the respective Member State
 * if there is no separate authority authorized to issue PID
 * @param issuingCountry Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider’s country or territory.
 * @param documentNumber A number for the PID, assigned by the PID Provider
 * @param issuingJurisdiction Country subdivision code of the jurisdiction that issued the PID, as defined
 * in ISO 3166-2:2020, Clause 8. The first part of the code SHALL be the same as the value for issuing_country.
 * @param issuanceDate Date (and possibly time) when the PID was issued.
 * @param trustAnchor This attribute indicates at least the URL at which a machine-readable version of the trust
 * anchor to be used for verifying the PID can be found or looked up
 */
data class PidMetaData(
    val personalAdministrativeNumber: AdministrativeNumber? = null,
    val expiryDate: LocalDate,
    val issuingAuthority: IssuingAuthority,
    val issuingCountry: IsoCountry,
    val documentNumber: DocumentNumber? = null,
    val issuingJurisdiction: IsoCountrySubdivision? = null,
    val issuanceDate: LocalDate? = null,
    val trustAnchor: URI? = null,
) {
    init {
        issuanceDate?.let {
            require(it < expiryDate) { "Issuance date should be before expiry date" }
        }

        if (issuingAuthority is IssuingAuthority.MemberState) {
            require(issuingAuthority.code == issuingCountry) {
                "IssuanceAuthority ${issuingAuthority.code.value} should be the same with issuingCountry = ${issuingCountry.value}"
            }
        }
    }
}
