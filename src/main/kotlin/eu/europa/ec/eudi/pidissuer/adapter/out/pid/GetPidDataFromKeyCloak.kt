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
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcAssurancePlaceOfBirth
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.port.input.Username
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.LocalDate
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.util.*
import kotlin.time.Duration.Companion.days

private val log = LoggerFactory.getLogger(GetPidDataFromKeyCloak::class.java)

data class Credentials(val username: String, val password: String?) {
    init {
        require(username.isNotBlank()) { "username cannot be blank" }
    }
}

@JvmInline
value class Realm(val value: String) {
    init {
        require(value.isNotBlank()) { "realm cannot be blank" }
    }
}

data class AdministrationClient(
    val realm: Realm,
    val client: Credentials,
    val admin: Credentials,
)

class GetPidDataFromKeyCloak(
    private val issuerCountry: IsoCountry,
    private val issuingJurisdiction: IsoCountrySubdivision?,
    private val clock: Clock,
    private val webClient: WebClient,
    private val keyCloak: Url,
    private val administrationClient: AdministrationClient,
    private val users: Realm,
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

        return getUserByUsername(username)
            ?.let { user ->
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
                    picture = null,
                    nationality = user.attributes["nationality"]?.firstOrNull(),
                )
            }
    }

    /**
     * Fetches the details of a user.
     *
     * @param username The username of the user the details of whose to fetch
     */
    private suspend fun getUserByUsername(username: String): UserRepresentation? {
        val accessToken = getAdminAccessToken()
        val url = URLBuilder()
            .takeFrom(keyCloak)
            .appendPathSegments("admin", "realms", users.value, "users")
            .apply {
                parameters.append("username", username)
            }
            .build()

        val users = webClient.get()
            .uri(url.toURI())
            .accept(MediaType.APPLICATION_JSON)
            .headers {
                it[HttpHeaders.AUTHORIZATION] = accessToken.toAuthorizationHeader()
            }
            .retrieve()
            .awaitBody<List<UserRepresentation>>()

        return if (users.size != 1) {
            null
        } else {
            users.first()
        }
    }

    /**
     * Gets an Access Token for the Admin user, using OAuth2.0 Password Grant.
     */
    private suspend fun getAdminAccessToken(): AccessToken {
        val tokenEndpoint = URLBuilder()
            .takeFrom(keyCloak)
            .appendPathSegments("realms", administrationClient.realm.value, "protocol", "openid-connect", "token")
            .build()
        val response = webClient.post()
            .uri(tokenEndpoint.toURI())
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON)
            .body(
                BodyInserters.fromFormData(
                    LinkedMultiValueMap<String, String>()
                        .apply {
                            add("grant_type", "password")
                            add("client_id", administrationClient.client.username)
                            administrationClient.client.password?.let { add("client_secret", it) }
                            add("username", administrationClient.admin.username)
                            administrationClient.admin.password?.let { add("password", it) }
                        },
                ),
            )
            .retrieve()
            .awaitBody<String>()

        return withContext(Dispatchers.Default) {
            AccessToken.parse(JSONObjectUtils.parse(response))
        }
    }

    private fun genPidMetaData(): PidMetaData {
        val (issuanceDate, expiryDate) = with(clock) {
            val now = now()
            now.toLocalDate() to (now + 100.days).toLocalDate()
        }

        return PidMetaData(
            personalAdministrativeNumber = AdministrativeNumber(UUID.randomUUID().toString()),
            expiryDate = expiryDate,
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

        val birthPlace = userInfo.placeOfBirth?.let { placeOfBirth ->
            if (null != placeOfBirth.country || null != placeOfBirth.region || null != placeOfBirth.locality) {
                PlaceOfBirth(
                    country = placeOfBirth.country?.let { IsoCountry(it) },
                    region = placeOfBirth.region?.let { State(it) },
                    locality = placeOfBirth.locality?.let { City(it) },
                )
            } else null
        }
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
        )

        val pidMetaData = genPidMetaData()

        return pid to pidMetaData
    }
}

@Serializable
@JsonIgnoreUnknownKeys
data class UserRepresentation(
    @Required val username: String,
    @Required val lastName: String,
    @Required val firstName: String,
    val attributes: Map<String, List<String>> = emptyMap(),
    @Required val email: String,
)

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
