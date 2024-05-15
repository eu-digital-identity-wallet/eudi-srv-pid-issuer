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
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.*
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Printer.prettyPrint
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.sdjwt.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.util.*

val PidSdJwtVcScope: Scope = Scope("${PID_DOCTYPE}_vc_sd_jwt")

private object Attributes {

    val BirthDateYear = AttributeDetails(
        name = "birthdate_year",
        mandatory = false,
    )
    val AgeEqualOrOver = AttributeDetails(
        name = "age_equal_or_over",
        display = mapOf(Locale.ENGLISH to "Age attestations"),
    )
    val AgeOver18 = AttributeDetails(
        name = "18",
        display = mapOf(Locale.ENGLISH to "Adult or minor"),
    )

    val AgeInYears = AttributeDetails(
        name = "age_in_years",
        display = mapOf(Locale.ENGLISH to "The subject’s current age in years."),
    )

    val IssuanceDate = AttributeDetails(
        name = "issuance_date",
        mandatory = true,
    )

    val pidAttributes = listOf(
        OidcFamilyName,
        OidcGivenName,
        OidcBirthDate,
        OidcAddressClaim.attribute,
        OidcGender,
        OidcAssuranceNationalities,
        OidcAssuranceBirthFamilyName,
        OidcAssuranceBirthGivenName,
        AgeEqualOrOver,
        AgeInYears,
        OidcAssurancePlaceOfBirth.attribute,
        IssuanceDate,
        BirthDateYear,
    )
}

fun pidSdJwtVcV1(signingAlgorithm: JWSAlgorithm): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSdJwtVcScope.value),
        type = SdJwtVcType(pidDocType(1)),
        display = pidDisplay,
        claims = Attributes.pidAttributes,
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        scope = PidSdJwtVcScope,
        proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
    )

typealias TimeDependant<F> = (ZonedDateTime) -> F

fun selectivelyDisclosed(
    pid: Pid,
    pidMetaData: PidMetaData,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
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
        plain("vct", vct.value)

        //
        // Selectively Disclosed claims
        //
        // https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-4
        sd(Attributes.IssuanceDate.name, pidMetaData.issuanceDate.toString()) // TODO Check issuance date
        sd(OidcGivenName.name, pid.givenName.value)
        // TODO Check also_known_as
        sd(OidcFamilyName.name, pid.familyName.value)
        sd(OidcBirthDate.name, pid.birthDate.toString())
        structured(Attributes.AgeEqualOrOver.name) {
            pid.ageOver18?.let { sd(Attributes.AgeOver18.name, it) }
        }

        // TODO
        //  Here we need a mapping in OIDC gender can be male, female on null
        //  In PID the use iso
        pid.gender?.let { sd(OidcGender.name, it.value.toInt()) }
        pid.nationality?.let {
            val nationalities = buildJsonArray { add(it.value) }
            sd(OidcAssuranceNationalities.name, nationalities)
        }
        pid.ageBirthYear?.let { sd(Attributes.AgeInYears.name, it.value) }
        pid.ageBirthYear?.let { sd(Attributes.BirthDateYear.name, it.value.toString()) }
        pid.familyNameBirth?.let { sd(OidcAssuranceBirthFamilyName.name, it.value) }
        pid.givenNameBirth?.let { sd(OidcAssuranceBirthGivenName.name, it.value) }
        pid.oidcAssurancePlaceOfBirth()?.let { placeOfBirth ->
            recursive(OidcAssurancePlaceOfBirth.NAME) {
                placeOfBirth.locality?.let { sd("locality", it) }
                placeOfBirth.region?.let { sd("region", it) }
                placeOfBirth.country?.let { sd("country", it) }
            }
        }
        pid.oidcAddressClaim()?.let { address ->
            recursive(OidcAddressClaim.NAME) {
                address.formatted?.let { sd("formatted", it) }
                address.country?.let { sd("country", it) }
                address.region?.let { sd("region", it) }
                address.locality?.let { sd("locality", it) }
                address.postalCode?.let { sd("postal_code", it) }
                address.streetAddress?.let { sd("street_address", it) }
                address.houseNumber?.let { sd("house_number", it) }
            }
        }
    }
}

private fun Pid.oidcAssurancePlaceOfBirth(): OidcAssurancePlaceOfBirth? =
    if (birthCountry != null || birthState != null || birthCity != null) {
        OidcAssurancePlaceOfBirth(
            country = birthCountry?.value,
            region = residentState?.value,
            locality = residentCity?.value,
        )
    } else null

private fun Pid.oidcAddressClaim(): OidcAddressClaim? =
    if (
        residentCountry != null || residentState != null ||
        residentCity != null || residentPostalCode != null ||
        residentStreet != null
    ) {
        OidcAddressClaim(
            country = residentCountry?.value,
            region = residentState?.value,
            locality = residentCity?.value,
            postalCode = residentPostalCode?.value,
            streetAddress = residentStreet?.value,
        )
    } else null

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val getPidData: GetPidData,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    private val calculateExpiresAt: TimeDependant<Instant>,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredential: StoreIssuedCredential,
) : IssueSpecificCredential<JsonElement> {

    private val log = LoggerFactory.getLogger(IssueSdJwtVcPid::class.java)
    private val validateProof = ValidateProof(credentialIssuerId)

    override val supportedCredential: SdJwtVcCredentialConfiguration = pidSdJwtVcV1(issuerSigningKey.signingAlgorithm)
    override val publicKey: JWK
        get() = issuerSigningKey.key.toPublicJWK()

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val sdJwt = encodePidInSdJwt(pid, pidMetaData, holderPubKey.await())

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null
        storeIssuedCredential(
            IssuedCredential(
                format = MSO_MDOC_FORMAT,
                type = supportedCredential.type.value,
                holder = with(pid) {
                    "${familyName.value} ${givenName.value}"
                },
                holderPublicKey = holderPubKey.await().toPublicJWK(),
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(JsonPrimitive(sdJwt), notificationId)
            .also {
                log.info("Successfully issued PID")
                log.debug("Issued PID data {}", it)
            }
    }

    context(Raise<IssueCredentialError>)
    private fun encodePidInSdJwt(pid: Pid, pidMetaData: PidMetaData, holderPubKey: JWK): String {
        val at = clock.instant().atZone(clock.zone)
        val sdJwtSpec = selectivelyDisclosed(
            pid = pid,
            pidMetaData = pidMetaData,
            vct = supportedCredential.type,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderPubKey,
            iat = at,
            exp = calculateExpiresAt(at),
            nbf = calculateNotUseBefore?.let { calculate -> calculate(at) },
        )
        val issuedSdJwt: SdJwt.Issuance<SignedJWT> = issuer.issue(sdJwtSpec).getOrElse {
            raise(Unexpected("Error while creating SD-JWT", it))
        }
        if (log.isInfoEnabled) {
            log.info(issuedSdJwt.prettyPrint())
        }

        return issuedSdJwt.serialize()
    }

    context(Raise<InvalidProof>)
    private suspend fun holderPubKey(
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): JWK {
        val key = validateProof(request.unvalidatedProof, expectedCNonce, supportedCredential)
        return extractJwkFromCredentialKey(key)
            .getOrElse {
                raise(InvalidProof("Unable to extract JWK from CredentialKey", it))
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
        val signer = ECDSASigner(issuerSigningKey.key)
        SdJwtIssuer.nimbus(sdJwtFactory, signer, issuerSigningKey.signingAlgorithm) {
            // SD-JWT VC requires the kid & typ header attributes
            // Check [here](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#name-jose-header)
            keyID(issuerSigningKey.key.keyID)
            type(JOSEObjectType("vc+sd-jwt"))
        }
    }
}

private object Printer {
    val json = Json { prettyPrint = true }
    private fun JsonElement.pretty(): String = json.encodeToString(this)
    fun SdJwt.Issuance<SignedJWT>.prettyPrint(): String {
        var str = "\nSD-JWT with ${disclosures.size} disclosures\n"
        disclosures.forEach { d ->
            val kind = when (d) {
                is Disclosure.ArrayElement -> "\t - ArrayEntry ${d.claim().value().pretty()}"
                is Disclosure.ObjectProperty -> "\t - ObjectProperty ${d.claim().first} = ${d.claim().second}"
            }
            str += kind + "\n"
        }
        str += "SD-JWT payload\n"
        str += json.parseToJsonElement(jwt.jwtClaimsSet.toString()).run {
            json.encodeToString(this)
        }
        return str
    }
}
