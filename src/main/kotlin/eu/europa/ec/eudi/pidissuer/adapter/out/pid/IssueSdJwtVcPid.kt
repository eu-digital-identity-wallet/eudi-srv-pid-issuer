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
import arrow.core.raise.Raise
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateJwtProof
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.sdjwt.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.*
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.util.*

val PidSdJwtVcScope: Scope = Scope("${PID_DOCTYPE}_vc_sd_jwt")

private object Attributes {
    val FamilyName = AttributeDetails(
        name = "family_name",
        display = mapOf(Locale.ENGLISH to "Current Family Name"),
    )
    val GivenName = AttributeDetails(
        name = "given_name",
        display = mapOf(Locale.ENGLISH to "Current First Names"),
    )

    val BirthDate = AttributeDetails(
        name = "birthdate",
        display = mapOf(Locale.ENGLISH to "Date of Birth"),
    )

    val BirthDateYear = AttributeDetails(
        name = "birthdate_year",
        mandatory = false,
    )
    val AgeOver18 = AttributeDetails(
        name = "age_over_18",
        display = mapOf(Locale.ENGLISH to "Adult or minor"),
    )

    val AgeInYears = AttributeDetails(
        name = "age_in_years",
        display = mapOf(Locale.ENGLISH to "The subject’s current age in years."),
    )
    val UniqueId = AttributeDetails(
        name = "sub",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Unique Identifier"),
    )

    val PlaceOfBirth = AttributeDetails(
        name = "place_of_birth",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The country, region, and locality"),
    )

    val Gender = AttributeDetails(
        name = "gender",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "PID User’s gender, using a value as defined in ISO/IEC 5218."),
    )

    val Nationalities = AttributeDetails(
        name = "nationalities",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Array of nationalities"),
    )

    val Address = AttributeDetails(
        name = "address",
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Resident country, region, locality and postal_code",
        ),
    )
    val IssuanceDate = AttributeDetails(
        name = "issuance_date",
        mandatory = true,
    )
    val BirthFamilyName = AttributeDetails(
        name = "birth_family_name",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
    )
    val BirthGivenName = AttributeDetails(
        name = "birth_given_name",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
    )

    val pidAttributes = listOf(
        FamilyName,
        GivenName,
        BirthDate,
        BirthFamilyName,
        BirthGivenName,
        AgeOver18,
        AgeInYears,
        UniqueId,
        PlaceOfBirth,
        Gender,
        Nationalities,
        Address,
        IssuanceDate,
        BirthDateYear,
    )
}

val PidSdJwtVcV1: SdJwtVcMetaData = SdJwtVcMetaData(
    type = SdJwtVcType(pidDocType(1)),
    display = pidDisplay,
    claims = Attributes.pidAttributes,
    cryptographicBindingMethodsSupported = listOf(
        CryptographicBindingMethod.Jwk(
            nonEmptySetOf(
                JWSAlgorithm.RS256,
                JWSAlgorithm.ES256,
            ),
        ),
    ),
    scope = PidSdJwtVcScope,
)

typealias TimeDependant<F> = (ZonedDateTime) -> F

fun selectivelyDisclosed(
    pid: Pid,
    pidMetaData: PidMetaData,
    credentialIssuerId: CredentialIssuerId,
    holderPubKey: JWK,
    iat: ZonedDateTime,
    exp: Instant,
    nbf: Instant?,
): SdObject {
    require(exp.epochSecond > iat.toInstant().epochSecond) { "exp should be after iat" }
    nbf?.let {
        require(nbf.epochSecond > iat.toInstant().epochSecond) { "nbe should be after iat" }
    }

    return sdJwt {
        //
        // Always disclosed claims
        //
        iss(credentialIssuerId.externalForm)
        iat(iat.toInstant().epochSecond)
        nbf?.let { nbf(it.epochSecond) }
        exp(exp.epochSecond)
        cnf(holderPubKey)
        plain("vct", PidSdJwtVcV1.type.value)
        plain(Attributes.UniqueId.name, pid.uniqueId.value)

        //
        // Selectively Disclosed claims
        //
        // https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-4
        sd(Attributes.IssuanceDate.name, pidMetaData.issuanceDate.toString())
        sd(Attributes.GivenName.name, pid.givenName.value)
        sd(Attributes.FamilyName.name, pid.familyName.value)
        sd(Attributes.BirthDate.name, pid.birthDate.toString())
        sd(Attributes.AgeOver18.name, pid.ageOver18)
        pid.gender?.let { sd(Attributes.Gender.name, it.value.toInt()) }
        pid.nationality?.let { sd(Attributes.Nationalities.name, JsonArray(listOf(JsonPrimitive(it.value)))) }
        pid.ageBirthYear?.let { sd(Attributes.AgeInYears.name, it.value) }
        pid.ageBirthYear?.let { sd(Attributes.BirthDateYear.name, it.value.toString()) }
        pid.familyNameBirth?.let { sd(Attributes.BirthFamilyName.name, it.value) }
        pid.givenNameBirth?.let { sd(Attributes.BirthGivenName.name, it.value) }
        if (pid.birthCountry != null || pid.birthState != null || pid.birthCity != null) {
            sd {
                putJsonObject(Attributes.PlaceOfBirth.name) {
                    pid.birthCountry?.let { put("country", it.value) }
                    pid.birthState?.let { put("region", it.value) }
                    pid.birthCity?.let { put("locality", it.value) }
                }
            }
        }
        // https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
        if (pid.residentCountry != null || pid.residentState != null ||
            pid.residentCity != null || pid.residentPostalCode != null
        ) {
            sd {
                putJsonObject(Attributes.Address.name) {
                    pid.residentCountry?.let { put("country", it.value) }
                    pid.residentState?.let { put("region", it.value) }
                    pid.residentCity?.let { put("locality", it.value) }
                    pid.residentPostalCode?.let { put("postal_code", it.value) }
                }
            }
        }
    }
}

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val signAlg: JWSAlgorithm,
    private val issuerKey: ECKey,
    private val getPidData: GetPidData,
    private val validateJwtProof: ValidateJwtProof,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    private val calculateExpiresAt: TimeDependant<Instant>,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
) : IssueSpecificCredential<JsonElement> {
    override val supportedCredential: CredentialMetaData
        get() = PidSdJwtVcV1

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val sdJwt = encodePidInSdJwt(pid, pidMetaData, holderPubKey.await())
        CredentialResponse.Issued(JsonPrimitive(sdJwt))
    }

    context(Raise<IssueCredentialError>)
    private fun encodePidInSdJwt(pid: Pid, pidMetaData: PidMetaData, holderPubKey: JWK): String {
        val at = clock.instant().atZone(clock.zone)
        val sdJwtSpec = selectivelyDisclosed(
            pid = pid,
            pidMetaData = pidMetaData,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderPubKey,
            iat = at,
            exp = calculateExpiresAt(at),
            nbf = calculateNotUseBefore?.let { calculate -> calculate(at) },
        )
        val issuedSdJwt = issuer.issue(sdJwtSpec).getOrElse {
            raise(IssueCredentialError.Unexpected("Error while creating SD-JWT", it))
        }
        return issuedSdJwt.serialize()
    }

    context(Raise<IssueCredentialError>)
    private suspend fun holderPubKey(
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): JWK {
        val key =
            when (val proof = request.unvalidatedProof) {
                is UnvalidatedProof.Jwt ->
                    validateJwtProof(
                        proof,
                        expectedCNonce,
                        supportedCredential.cryptographicSuitesSupported(),
                    ).getOrElse { raise(IssueCredentialError.InvalidProof("Proof is not valid", it)) }

                is UnvalidatedProof.Cwt -> raise(IssueCredentialError.InvalidProof("Supporting only JWT proof"))
            }

        return extractJwkFromCredentialKey(key)
            .getOrElse {
                raise(IssueCredentialError.InvalidProof("Unable to extract JWK from CredentialKey", it))
            }
    }

    /**
     * Creates a Nimbus-based SD-JWT issuer
     * according to the requirements of SD-JWT VC
     * - No decoys
     * - JWS header kid should contain the id of issuer's key
     * - JWS header typ should contain value "vs+sd-jwt"
     * In addition the issuer will use the config to select
     * [HashAlgorithm], [JWSAlgorithm] and [issuer's key][ECKey]
     */
    private val issuer: SdJwtIssuer<SignedJWT> by lazy {
        // SD-JWT VC requires no decoys

        val sdJwtFactory = SdJwtFactory(hashAlgorithm = hashAlgorithm, numOfDecoysLimit = 0)
        val signer = ECDSASigner(issuerKey)
        SdJwtIssuer.nimbus(sdJwtFactory, signer, signAlg) {
            // SD-JWT VC requires the kid & typ header attributes
            // Check [here](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#name-jose-header)
            keyID(issuerKey.keyID)
            type(JOSEObjectType("vc+sd-jwt"))
        }
    }
}
