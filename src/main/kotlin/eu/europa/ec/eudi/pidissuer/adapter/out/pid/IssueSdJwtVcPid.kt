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

import arrow.core.nonEmptySetOf
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateJwtProof
import eu.europa.ec.eudi.pidissuer.adapter.out.sdjwt.TimeDependant
import eu.europa.ec.eudi.pidissuer.adapter.out.sdjwt.createSdJwtVcIssuer
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.sdjwt.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.put
import java.time.Clock
import java.time.Instant
import java.time.LocalTime
import java.time.ZonedDateTime
import java.time.temporal.ChronoField

val PidSdJwtVcScope: Scope = Scope("${PID_DOCTYPE}_vc_sd_jwt")

val PidSdJwtVcV1: SdJwtVcMetaData = SdJwtVcMetaData(
    type = SdJwtVcType(pidDocType(1)),
    display = pidDisplay,
    claims = pidAttributes,
    cryptographicBindingMethodsSupported = listOf(
        CryptographicBindingMethod.Jwk(
            nonEmptySetOf(
                JWSAlgorithm.RS256,
                JWSAlgorithm.ES256K,
            ),
        ),
    ),
    scope = PidSdJwtVcScope,
)

fun Pair<Pid, PidMetaData>.asSdObjectAt(iat: ZonedDateTime): SdObject {
    val (pid, pidMetaData) = this

    fun Pid.includePlaceOfBirth() = birthPlace != null || birthState != null || birthCity != null
    fun Pid.includeAddress() =
        residentCountry != null ||
            residentState != null ||
            residentCity != null ||
            residentPostalCode != null ||
            residentHouseNumber != null

    return sdJwt {
        sub(pid.uniqueId.value)
        sd("given_name", pid.givenName.value)
        sd("family_name", pid.familyName.value)
        sd("birthdate", pid.birthDate.toString())
        pid.familyNameBirth?.let { sd("birth_family_name", it.value) }
        pid.givenNameBirth?.let { sd("birth_given_name", it.value) }

        if (pid.includePlaceOfBirth()) {
            structured("place_of_birth") {
                pid.birthCountry?.let { sd("birth_country", it.value) }
                pid.birthState?.let { sd("birth_state", it.value) }
                pid.birthCity?.let { sd("birth_city", it.value) }
            }
        }
        if (pid.includeAddress()) {
            structured("address") {
                pid.residentCountry?.let { sd("resident_country", it.value) }
                pid.residentState?.let { sd("resident_state", it.value) }
                pid.residentCity?.let { sd("resident_city", it.value) }
                pid.residentPostalCode?.let { sd("resident_postal_code", it.value) }
                pid.residentHouseNumber?.let { sd("resident_house_number", it) }
            }
        }
        pid.gender?.let { sd("gender", it.value.toInt()) }
        pid.nationality?.let { sd("nationalities", JsonArray(listOf(JsonPrimitive(it.value)))) }
        sd {
            val age = iat.year - pid.birthDate.get(ChronoField.YEAR)
            put("is_over_18", age >= 18)
            pid.ageBirthYear?.let { put("age_birth_year", it.value) }
        }
    }
}

/**
 * Service for issuing PID SD JWT credential
 */
fun issueSdJwtVcPid(
    credentialIssuerId: CredentialIssuerId,
    clock: Clock,
    hashAlgorithm: HashAlgorithm,
    signAlg: JWSAlgorithm,
    issuerKey: ECKey,
    expiresAt: TimeDependant<Instant>? = { iat -> iat.plusYears(2).with(LocalTime.MIDNIGHT).toInstant() },
    notUseBefore: TimeDependant<Instant>? = { iat -> iat.plusSeconds(10).toInstant() },
    getPidData: GetPidData,
    validateJwtProof: ValidateJwtProof,
    extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
): IssueSpecificCredential<JsonElement> = createSdJwtVcIssuer(
    supportedCredential = PidSdJwtVcV1,
    credentialIssuerId = credentialIssuerId,
    clock = clock,
    hashAlgorithm = hashAlgorithm,
    signAlg = signAlg,
    issuerKey = issuerKey,
    expiresAt = expiresAt,
    notUseBefore = notUseBefore,
    validateJwtProof = validateJwtProof,
    extractJwkFromCredentialKey = extractJwkFromCredentialKey,
    getData = { authorizationContext -> getPidData(authorizationContext.accessToken) },
    createSdJwt = { pid -> pid::asSdObjectAt },

)
