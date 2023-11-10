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

import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.time.Clock
import java.time.LocalDate

private val log = LoggerFactory.getLogger(GetPidDataFromAuthServer::class.java)

class GetPidDataFromAuthServer(
    authorizationServerUserInfoEndPoint: HttpsUrl,
    private val issuerCountry: IsoCountry,
    private val clock: Clock,
) : GetPidData {

    private val jsonSupport: Json by lazy {
        Json { prettyPrint = true }
    }
    private val webClient: WebClient =
        WebClient.create(authorizationServerUserInfoEndPoint.externalForm)

    override suspend fun invoke(accessToken: String): Pair<Pid, PidMetaData>? {
        log.info("Trying to get PID Data from userinfo endpoint ...")
        val userInfo = userInfo(accessToken).also {
            if (log.isInfoEnabled) log.info(jsonSupport.encodeToString(it))
        }
        return pid(userInfo)
    }

    private suspend fun userInfo(accessToken: String): JsonObject =
        webClient.get().accept(MediaType.APPLICATION_JSON)
            .headers { headers -> headers.setBearerAuth(accessToken) }
            .retrieve()
            .awaitBody<JsonObject>()

    private fun genPidMetaData(): PidMetaData {
        val issuanceDate = LocalDate.now(clock)
        return PidMetaData(
            expiryDate = issuanceDate.plusDays(100).asDateAndPossiblyTime(),
            issuanceDate = issuanceDate.asDateAndPossiblyTime(),
            issuingCountry = issuerCountry,
            issuingAuthority = IssuingAuthority.AdministrativeAuthority(" Foo bat administrative authority"),
            documentNumber = null,
            administrativeNumber = null,
            issuingJurisdiction = null,
            portrait = null,
        )
    }

    private fun pid(json: JsonObject): Pair<Pid, PidMetaData>? = runCatching {
        requireNotNull(json["family_name"]) { "Missing family_name" }
        requireNotNull(json["given_name"]) { "Missing given_name" }
        requireNotNull(json["sub"]) { "Missing sub" }

        val pid = Pid(
            familyName = FamilyName(json["family_name"]!!.jsonPrimitive.content),
            givenName = GivenName(json["given_name"]!!.jsonPrimitive.content),
            birthDate = LocalDate.now(),
            ageOver18 = true,
            uniqueId = UniqueId(json["sub"]!!.jsonPrimitive.content),
        )

        val pidMetaData = genPidMetaData()

        return pid to pidMetaData
    }.getOrNull()
}

private fun LocalDate.asDateAndPossiblyTime(): DateAndPossiblyTime = DateAndPossiblyTime(this, null)
