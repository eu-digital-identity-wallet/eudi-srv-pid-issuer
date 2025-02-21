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

import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcAssurancePlaceOfBirth
import eu.europa.ec.eudi.pidissuer.port.input.Username
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.keycloak.admin.client.Keycloak
import org.keycloak.representations.idm.UserRepresentation
import org.slf4j.LoggerFactory
import java.time.*
import java.util.*
import kotlin.math.ceil

private val log = LoggerFactory.getLogger(GetPidDataFromAuthServer::class.java)

class GetPidDataFromAuthServer(
    private val issuerCountry: IsoCountry,
    private val issuingJurisdiction: IsoCountrySubdivision?,
    private val clock: Clock,
    private val keycloak: Keycloak,
    private val userRealm: String,
) : GetPidData {
    init {
        issuingJurisdiction?.let {
            require(it.startsWith(issuerCountry.value)) {
                "Issuing Jurisdiction must be within the Issuing Country"
            }
        }
    }

    override suspend fun invoke(username: Username): Pair<Pid, PidMetaData>? {
        log.info("Trying to get PID Data from Keycloak ...")
        val userInfo = userInfo(username).also {
            if (log.isInfoEnabled) log.info(it.toString())
        }
        return userInfo?.let { pid(it) }
    }

    private suspend fun userInfo(username: Username): UserInfo? {
        fun UserRepresentation.address(): AddressData? {
            val street = attributes["street"]?.firstOrNull()
            val houseNumber = attributes["address_house_number"]?.firstOrNull()
            val locality = attributes["locality"]?.firstOrNull()
            val region = attributes["region"]?.firstOrNull()
            val postalCode = attributes["postal_code"]?.firstOrNull()
            val country = attributes["country"]?.firstOrNull()
            val formatted = attributes["formatted"]?.firstOrNull()

            return if (street != null || houseNumber != null ||
                locality != null || region != null ||
                postalCode != null || country != null ||
                formatted != null
            ) {
                AddressData(
                    streetAddress = street,
                    houseNumber = houseNumber,
                    locality = locality,
                    region = region,
                    postalCode = postalCode,
                    country = country,
                    formatted = formatted,
                )
            } else {
                null
            }
        }

        fun UserRepresentation.birthPlace(): OidcAssurancePlaceOfBirth? {
            val birthPlace = attributes["birth_place"]?.firstOrNull()
            val birthCountry = attributes["birth_country"]?.firstOrNull()
            val birthState = attributes["birth_state"]?.firstOrNull()
            val birthCity = attributes["birth_city"]?.firstOrNull()

            return if (birthPlace != null || birthCountry != null || birthState != null || birthCity != null) {
                OidcAssurancePlaceOfBirth(
                    locality = birthPlace ?: birthCity,
                    region = birthState,
                    country = birthCountry,
                )
            } else null
        }

        return withContext(Dispatchers.IO) {
            val users = keycloak.realm(userRealm)
                .users()
                .search(username)

            if (users.size != 1) {
                null
            } else {
                val user = users[0]
                UserInfo(
                    familyName = user.lastName,
                    givenName = user.firstName,
                    birthFamilyName = user.attributes["birth_family_name"]?.firstOrNull(),
                    birthGivenName = user.attributes["birth_given_name"]?.firstOrNull(),
                    sub = user.username,
                    email = user.email,
                    address = user.address(),
                    birthDate = user.attributes["birthdate"]?.firstOrNull(),
                    gender = user.attributes["gender"]?.firstOrNull()?.toUInt(),
                    genderAsString = user.attributes["gender_as_string"]?.firstOrNull(),
                    placeOfBirth = user.birthPlace(),
                    ageOver18 = user.attributes["age_over_18"]?.firstOrNull()?.toBoolean(),
                    picture = null,
                    nationality = user.attributes["nationality"]?.firstOrNull(),
                )
            }
        }
    }

    private fun genPidMetaData(): PidMetaData {
        val issuanceDate = LocalDate.now(clock)
        return PidMetaData(
            personalAdministrativeNumber = AdministrativeNumber(UUID.randomUUID().toString()),
            expiryDate = issuanceDate.plusDays(100),
            issuingAuthority = IssuingAuthority.AdministrativeAuthority("${issuerCountry.value} Administrative authority"),
            issuingCountry = issuerCountry,
            documentNumber = DocumentNumber(UUID.randomUUID().toString()),
            issuingJurisdiction = issuingJurisdiction,
            issuanceDate = issuanceDate,
            trustAnchor = null,
        )
    }

    private fun pid(userInfo: UserInfo): Pair<Pid, PidMetaData> {
        val birthDate = requireNotNull(userInfo.birthDate) {
            "missing required attribute 'birthDate'"
        }.let { LocalDate.parse(it) }
        val ageInYears = Duration.between(birthDate.atStartOfDay(clock.zone), ZonedDateTime.now(clock))
            .takeIf { !it.isZero && !it.isNegative }
            ?.let { ceil(it.toDays().toDouble() / 365).toUInt() }
        val birthPlace = userInfo.placeOfBirth?.let { placeOfBirth ->
            listOfNotNull(placeOfBirth.locality, placeOfBirth.region, placeOfBirth.region)
                .joinToString(separator = ", ")
                .takeIf { it.isNotBlank() }
        } ?: "Not known"
        val nationality = IsoCountry(requireNotNull(userInfo.nationality) { "missing required attribute 'nationality'" })
        val pid = Pid(
            familyName = FamilyName(userInfo.familyName),
            givenName = GivenName(userInfo.givenName),
            birthDate = birthDate,
            birthPlace = birthPlace,
            nationalities = nonEmptyListOf(nationality),
            residentAddress = userInfo.address?.formatted,
            residentCountry = userInfo.address?.country?.let { IsoCountry(it) },
            residentState = userInfo.address?.region?.let { State(it) },
            residentCity = userInfo.address?.locality?.let { City(it) },
            residentPostalCode = userInfo.address?.postalCode?.let { PostalCode(it) },
            residentStreet = userInfo.address?.streetAddress?.let { Street(it) },
            residentHouseNumber = userInfo.address?.houseNumber,
            portrait = null,
            familyNameBirth = userInfo.birthFamilyName?.let { FamilyName(it) },
            givenNameBirth = userInfo.birthGivenName?.let { GivenName(it) },
            sex = userInfo.gender?.let { IsoGender(it) },
            emailAddress = userInfo.email,
            mobilePhoneNumber = null,
            ageOver18 = userInfo.ageOver18 ?: false,
            ageInYears = ageInYears,
            ageBirthYear = Year.from(birthDate),
        )

        val pidMetaData = genPidMetaData()

        return pid to pidMetaData
    }
}

private data class UserInfo(
    val familyName: String,
    val givenName: String,
    val birthFamilyName: String? = null,
    val birthGivenName: String? = null,
    val sub: String,
    val email: String? = null,
    val address: AddressData? = null,
    val birthDate: String? = null,
    val gender: UInt? = null,
    val genderAsString: String? = null,
    val placeOfBirth: OidcAssurancePlaceOfBirth? = null,
    val ageOver18: Boolean? = null,
    val picture: String? = null,
    val nationality: String? = null,
)

private data class AddressData(
    val streetAddress: String? = null,
    val locality: String? = null,
    val region: String? = null,
    val postalCode: String? = null,
    val country: String? = null,
    val formatted: String? = null,
    val houseNumber: String? = null,
)
