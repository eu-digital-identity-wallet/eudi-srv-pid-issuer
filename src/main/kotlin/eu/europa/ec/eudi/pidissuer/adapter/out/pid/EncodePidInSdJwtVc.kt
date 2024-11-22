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

import arrow.core.raise.Raise
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.*
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.sdjwt.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcGender as OidcGenderAttribute

private val log = LoggerFactory.getLogger(EncodePidInSdJwtVc::class.java)

class EncodePidInSdJwtVc(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val calculateExpiresAt: TimeDependant<Instant>,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
    private val vct: SdJwtVcType,
) {

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
        val sdJwtFactory = SdJwtFactory(hashAlgorithm = hashAlgorithm, fallbackMinimumDigests = null)
        val signer = ECDSASigner(issuerSigningKey.key)
        SdJwtIssuer.nimbus(sdJwtFactory, signer, issuerSigningKey.signingAlgorithm) {
            type(JOSEObjectType("vc+sd-jwt"))
        }
    }

    context(Raise<IssueCredentialError>)
    fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: JWK,
    ): String {
        val at = clock.instant().atZone(clock.zone)
        val sdJwtSpec = selectivelyDisclosed(
            pid = pid,
            pidMetaData = pidMetaData,
            vct = vct,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderKey,
            iat = at,
            exp = calculateExpiresAt(at),
            nbf = calculateNotUseBefore?.let { calculate -> calculate(at) },
        )
        val issuedSdJwt: SdJwt.Issuance<SignedJWT> = issuer.issue(sdJwtSpec).getOrElse {
            raise(Unexpected("Error while creating SD-JWT", it))
        }
        if (log.isInfoEnabled) {
            log.info(with(Printer) { issuedSdJwt.prettyPrint() })
        }

        return issuedSdJwt.serialize()
    }
}

private fun selectivelyDisclosed(
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
        sd(OidcFamilyName.name, pid.familyName.value)
        sd(OidcGivenName.name, pid.givenName.value)
        sd(OidcBirthDate.name, pid.birthDate.toString())
        structured(Attributes.AgeEqualOrOver.name) {
            pid.ageOver18?.let { sd(Attributes.AgeOver18.name, it) }
        }
        pid.ageInYears?.let { sd(Attributes.AgeInYears.name, it.toInt()) }
        pid.ageBirthYear?.let { sd(Attributes.AgeBirthYear.name, it.value.toString()) }
        pid.familyNameBirth?.let { sd(OidcAssuranceBirthFamilyName.name, it.value) }
        pid.givenNameBirth?.let { sd(OidcAssuranceBirthGivenName.name, it.value) }

        pid.oidcAssurancePlaceOfBirth()?.let { placeOfBirth ->
            // TODO double-check the names of the nested fields
            structured(OidcAssurancePlaceOfBirth.NAME) {
                placeOfBirth.locality?.let { sd("locality", it) }
                placeOfBirth.region?.let { sd("region", it) }
                placeOfBirth.country?.let { sd("country", it) }
            }
        }
        pid.oidcAddressClaim()?.let { address ->
            structured(OidcAddressClaim.NAME) {
                address.formatted?.let { sd("formatted", it) }
                address.country?.let { sd("country", it) }
                address.region?.let { sd("region", it) }
                address.locality?.let { sd("locality", it) }
                address.postalCode?.let { sd("postal_code", it) }
                address.streetAddress?.let { sd("street_address", it) }
                address.houseNumber?.let { sd("house_number", it) }
            }
        }
        pid.gender?.let { sd(OidcGenderAttribute.name, it.toOidGender().value) }
        pid.nationality?.let {
            val nationalities = buildJsonArray { add(it.value) }
            sd(OidcAssuranceNationalities.name, nationalities)
        }
        sd(IssuingAuthorityAttribute.name, pidMetaData.issuingAuthority.valueAsString())
        pidMetaData.documentNumber?.let { sd(DocumentNumberAttribute.name, it.value) }
        pidMetaData.administrativeNumber?.let { sd(AdministrativeNumberAttribute.name, it.value) }
        sd(IssuingCountryAttribute.name, pidMetaData.issuingCountry.value)
        pidMetaData.issuingJurisdiction?.let { sd(IssuingJurisdictionAttribute.name, it) }
    }
}

private fun Pid.oidcAssurancePlaceOfBirth(): OidcAssurancePlaceOfBirth? =
    if (birthCountry != null || birthState != null || birthCity != null) {
        // TODO
        //  birth_lace and birth_city are both mapped to locality
        //  https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/pull/160#discussion_r1853638874
        OidcAssurancePlaceOfBirth(
            locality = birthCity?.value,
            country = birthCountry?.value,
            region = residentState?.value,
        )
    } else null

private fun Pid.oidcAddressClaim(): OidcAddressClaim? =
    if (
        residentAddress != null || residentCountry != null || residentState != null ||
        residentCity != null || residentPostalCode != null ||
        residentStreet != null || residentHouseNumber != null
    ) {
        OidcAddressClaim(
            formatted = residentAddress,
            country = residentCountry?.value,
            region = residentState?.value,
            locality = residentCity?.value,
            postalCode = residentPostalCode?.value,
            streetAddress = residentStreet?.value,
            houseNumber = residentHouseNumber,
        )
    } else null

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

/**
 * Converts an [IsoGender] to an [OidcGender].
 */
private fun IsoGender.toOidGender(): OidcGender =
    when (value) {
        0u -> OidcGender("not known")
        1u -> OidcGender.Male
        2u -> OidcGender.Female
        9u -> OidcGender("not applicable")
        else -> OidcGender(value.toString())
    }
