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
import eu.europa.ec.eudi.pidissuer.adapter.out.webclient.WebClients
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.time.Clock
import java.time.LocalDate

private val log = LoggerFactory.getLogger(GetPidDataFromAuthServer::class.java)

class GetPidDataFromAuthServer private constructor(
    private val issuerCountry: IsoCountry,
    private val clock: Clock,
    private val webClient: WebClient,
) : GetPidData {

    private val jsonSupport: Json by lazy {
        Json { prettyPrint = true }
    }

    override suspend fun invoke(accessToken: String): Pair<Pid, PidMetaData>? {
        log.info("Trying to get PID Data from userinfo endpoint ...")
        val userInfo = userInfo(accessToken).also {
            if (log.isInfoEnabled) log.info(jsonSupport.encodeToString(it))
        }
        return pid(userInfo)
    }

    private suspend fun userInfo(accessToken: String): UserInfo =
        webClient.get().accept(MediaType.APPLICATION_JSON)
            .headers { headers -> headers.setBearerAuth(accessToken) }
            .retrieve()
            .awaitBody<UserInfo>()

    private fun genPidMetaData(): PidMetaData {
        val issuanceDate = LocalDate.now(clock)
        return PidMetaData(
            expiryDate = issuanceDate.plusDays(100),
            issuanceDate = issuanceDate,
            issuingCountry = issuerCountry,
            issuingAuthority = IssuingAuthority.AdministrativeAuthority(" Foo bat administrative authority"),
            documentNumber = null,
            administrativeNumber = null,
            issuingJurisdiction = null,
            portrait = null,
        )
    }

    private fun pid(userInfo: UserInfo): Pair<Pid, PidMetaData> {
        val pid = Pid(
            familyName = FamilyName(userInfo.familyName),
            givenName = GivenName(userInfo.givenName),
            birthDate = LocalDate.parse(userInfo.birthDate),
            ageOver18 = userInfo.ageOver18 ?: false,
            gender = userInfo.gender?.let { IsoGender(it) },
            residentCountry = userInfo.address?.country?.let { IsoCountry(it) },
            residentState = userInfo.address?.region?.let { State(it) },
            residentPostalCode = userInfo.address?.postalCode?.let { PostalCode(it) },
            residentCity = userInfo.address?.locality?.let { City(it) },
            residentStreet = userInfo.address?.street?.let { Street(it) },
            birthCity = userInfo.placeOfBirth?.locality?.let { City(it) },
            birthCountry = userInfo.placeOfBirth?.country?.let { IsoCountry(it) },
            birthState = userInfo.placeOfBirth?.region?.let { State(it) },
        )

        val pidMetaData = genPidMetaData()

        return pid to pidMetaData
    }

    companion object {

        /**
         * Creates a new [GetPidDataFromAuthServer] using the provided data.
         */
        operator fun invoke(
            authorizationServerUserInfoEndPoint: HttpsUrl,
            issuerCountry: IsoCountry,
            clock: Clock,
        ): GetPidDataFromAuthServer =
            GetPidDataFromAuthServer(
                issuerCountry,
                clock,
                WebClients.default {
                    baseUrl(authorizationServerUserInfoEndPoint.externalForm)
                },
            )

        /**
         * Creates a new *insecure* [GetPidDataFromAuthServer] that trusts all certificates.
         */
        fun insecure(
            authorizationServerUserInfoEndPoint: HttpsUrl,
            issuerCountry: IsoCountry,
            clock: Clock,
        ): GetPidDataFromAuthServer {
            return GetPidDataFromAuthServer(
                issuerCountry,
                clock,
                WebClients.insecure {
                    baseUrl(authorizationServerUserInfoEndPoint.externalForm)
                },
            )
        }
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
