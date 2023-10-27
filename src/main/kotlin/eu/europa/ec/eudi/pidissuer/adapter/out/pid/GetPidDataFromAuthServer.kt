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

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.net.URL
import java.time.LocalDate

class GetPidDataFromAuthServer(
    private val authorizationServerUserInfoEndPoint: URL,
) : GetPidData {
    private val log = LoggerFactory.getLogger(GetPidDataFromAuthServer::class.java)
    override suspend fun invoke(accessToken: String): Pid? {
        log.info("Trying to get PID Data from userinfo endpoint ...")
        val webClient: WebClient = WebClient.create(authorizationServerUserInfoEndPoint.toString())
        val userInfo = webClient.get().accept(MediaType.APPLICATION_JSON)
            .headers { it.setBearerAuth(accessToken) }
            .retrieve()
            .awaitBody<JsonObject>()
        if (log.isInfoEnabled) {
            log.info(jsonSupport.encodeToString(userInfo))
        }
        return pid(userInfo).also {
            log.info("$it")
        }
    }

    private fun pid(json: JsonObject): Pid? = runCatching {
        Pid(
            familyName = FamilyName(json["family_name"]!!.jsonPrimitive.content),
            givenName = GivenName(json["given_name"]!!.jsonPrimitive.content),
            birthDate = LocalDate.now(),
            ageOver18 = true,
            uniqueId = UniqueId(json["sub"]!!.jsonPrimitive.content),

        )
    }.getOrNull()

    private val jsonSupport = Json {
        prettyPrint = true
    }
}
