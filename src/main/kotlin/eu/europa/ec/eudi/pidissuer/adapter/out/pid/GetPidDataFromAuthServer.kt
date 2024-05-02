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

import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcAddressClaim
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcAssurancePlaceOfBirth
import eu.europa.ec.eudi.pidissuer.port.input.Username
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.keycloak.admin.client.Keycloak
import org.keycloak.representations.idm.UserRepresentation
import org.slf4j.LoggerFactory
import java.time.*
import kotlin.math.ceil

private val log = LoggerFactory.getLogger(GetPidDataFromAuthServer::class.java)

class GetPidDataFromAuthServer(
    private val issuerCountry: IsoCountry,
    private val clock: Clock,
    private val keycloak: Keycloak,
    private val userRealm: String,
) : GetPidData {

    private val jsonSupport: Json by lazy {
        Json { prettyPrint = true }
    }

    override suspend fun invoke(username: Username): Pair<Pid, PidMetaData>? {
        log.info("Trying to get PID Data from Keycloak ...")
        val userInfo = userInfo(username).also {
            if (log.isInfoEnabled) log.info(jsonSupport.encodeToString(it))
        }
        return userInfo?.let { pid(it) }
    }

    private suspend fun userInfo(username: Username): UserInfo? {
        fun UserRepresentation.address(): OidcAddressClaim? {
            val street = attributes["street"]?.firstOrNull()
            val locality = attributes["locality"]?.firstOrNull()
            val region = attributes["region"]?.firstOrNull()
            val postalCode = attributes["postal_code"]?.firstOrNull()
            val country = attributes["country"]?.firstOrNull()
            val formatted = attributes["formatted"]?.firstOrNull()

            return if (street != null || locality != null || region != null || postalCode != null || country != null || formatted != null) {
                OidcAddressClaim(
                    street = street,
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
                    sub = user.username,
                    email = user.email,
                    address = user.address(),
                    birthDate = user.attributes["birthdate"]?.firstOrNull(),
                    gender = user.attributes["gender"]?.firstOrNull()?.toUInt(),
                    placeOfBirth = null,
                    ageOver18 = user.attributes["age_over_18"]?.firstOrNull()?.toBoolean(),
                    picture = null,
                )
            }
        }
    }

    private fun genPidMetaData(): PidMetaData {
        val issuanceDate = LocalDate.now(clock)
        return PidMetaData(
            expiryDate = issuanceDate.plusDays(100),
            issuanceDate = issuanceDate,
            issuingCountry = issuerCountry,
            issuingAuthority = IssuingAuthority.AdministrativeAuthority("Foo bar administrative authority"),
            documentNumber = null,
            administrativeNumber = null,
            issuingJurisdiction = null,
        )
    }

    private fun pid(userInfo: UserInfo): Pair<Pid, PidMetaData> {
        val birthDate = requireNotNull(userInfo.birthDate) {
            "missing required attribute 'birthDate'"
        }.let { LocalDate.parse(it) }
        val ageInYears = Duration.between(birthDate.atStartOfDay(clock.zone), ZonedDateTime.now(clock))
            .takeIf { !it.isZero && !it.isNegative }
            ?.let { ceil(it.toDays().toDouble() / 365).toUInt() }
        val pid = Pid(
            familyName = FamilyName(userInfo.familyName),
            givenName = GivenName(userInfo.givenName),
            birthDate = birthDate,
            ageOver18 = userInfo.ageOver18 ?: false,
            ageBirthYear = Year.from(birthDate),
            ageInYears = ageInYears,
            residentAddress = userInfo.address?.formatted,
            residentStreet = userInfo.address?.street?.let { Street(it) },
            residentCountry = userInfo.address?.country?.let { IsoCountry(it) },
            residentState = userInfo.address?.region?.let { State(it) },
            residentCity = userInfo.address?.locality?.let { City(it) },
            residentPostalCode = userInfo.address?.postalCode?.let { PostalCode(it) },
            birthCity = userInfo.placeOfBirth?.locality?.let { City(it) },
            birthCountry = userInfo.placeOfBirth?.country?.let { IsoCountry(it) },
            birthState = userInfo.placeOfBirth?.region?.let { State(it) },
            gender = userInfo.gender?.let { IsoGender(it) },
        )

        val pidMetaData = genPidMetaData()

        return pid to pidMetaData
    }
}

@Serializable
private data class UserInfo(
    @Required @SerialName("family_name") val familyName: String,
    @Required @SerialName("given_name") val givenName: String,
    @Required val sub: String,
    val email: String? = null,
    @SerialName(OidcAddressClaim.NAME) val address: OidcAddressClaim? = null,
    @SerialName("birthdate") val birthDate: String? = null,
    @SerialName("gender") val gender: UInt? = null,
    @SerialName(OidcAssurancePlaceOfBirth.NAME) val placeOfBirth: OidcAssurancePlaceOfBirth? = null,
    @SerialName("age_over_18") val ageOver18: Boolean? = null,
    val picture: String? = null,
)
