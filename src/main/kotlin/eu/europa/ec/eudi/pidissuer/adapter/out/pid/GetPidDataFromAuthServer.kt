package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import eu.europa.ec.eudi.pidissuer.domain.pid.FamilyName
import eu.europa.ec.eudi.pidissuer.domain.pid.GivenName
import eu.europa.ec.eudi.pidissuer.domain.pid.Pid
import eu.europa.ec.eudi.pidissuer.domain.pid.UniqueId
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
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
    private val authorizationServerUserInfoEndPoint: URL
) : GetPidData {
    val log = LoggerFactory.getLogger(GetPidDataFromAuthServer::class.java)
    override suspend fun invoke(accessToken: String): Pid? {
        log.info("Trying to get PID Data from userinfo endpoint ...")
        val webClient: WebClient = WebClient.create(authorizationServerUserInfoEndPoint.toString())
        val userInfo = webClient.get().accept(MediaType.APPLICATION_JSON)
            .header("Authorization", accessToken)
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
            uniqueId = UniqueId(json["sub"]!!.jsonPrimitive.content)


        )

    }.getOrNull()

    private val jsonSupport = Json {
        prettyPrint = true
    }
}