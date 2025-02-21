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

import arrow.core.Either
import arrow.core.raise.either
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.certificate
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.*
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.vc.sanOfDNSName
import eu.europa.ec.eudi.sdjwt.vc.sanOfUniformResourceIdentifier
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

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
        val x509CertChain = run {
            val certificate = issuerSigningKey.certificate
            if (certificate.containsSanUri(credentialIssuerId.value) || certificate.containsSanDns(credentialIssuerId.value)) {
                issuerSigningKey.key.x509CertChain
            } else {
                null
            }
        }

        NimbusSdJwtOps.issuer(sdJwtFactory, signer, issuerSigningKey.signingAlgorithm) {
            // TODO: This will change to dc+sd-jwt in a future release
            type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT))
            keyID(issuerSigningKey.key.keyID)
            x509CertChain(x509CertChain)
        }
    }

    suspend fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: JWK,
    ): Either<IssueCredentialError, String> = either {
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
        val issuedSdJwt: SdJwt<SignedJWT> = issuer.issue(sdJwtSpec).getOrElse {
            raise(Unexpected("Error while creating SD-JWT", it))
        }
        if (log.isInfoEnabled) {
            log.info(with(Printer) { issuedSdJwt.prettyPrint() })
        }

        with(NimbusSdJwtOps) {
            issuedSdJwt.serialize()
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
private val base64UrlNoPadding by lazy { Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT) }

@OptIn(ExperimentalEncodingApi::class)
private fun selectivelyDisclosed(
    pid: Pid,
    pidMetaData: PidMetaData,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
    holderPubKey: JWK,
    iat: ZonedDateTime,
    exp: Instant,
    nbf: Instant?,
): DisclosableObject {
    require(exp.epochSecond > iat.toInstant().epochSecond) { "exp should be after iat" }
    nbf?.let {
        require(nbf.epochSecond > iat.toInstant().epochSecond) { "nbe should be after iat" }
    }

    return sdJwt {
        //
        // Always disclosed claims
        //
        claim(RFC7519.ISSUER, credentialIssuerId.externalForm)
        claim(RFC7519.ISSUED_AT, iat.toInstant().epochSecond)
        nbf?.let { claim(RFC7519.NOT_BEFORE, it.epochSecond) }
        claim(RFC7519.EXPIRATION_TIME, exp.epochSecond)
        cnf(holderPubKey)
        claim(SdJwtVcSpec.VCT, vct.value)

        //
        // Selectively Disclosed claims
        //
        sdClaim(OidcFamilyName.name, pid.familyName.value)
        sdClaim(OidcGivenName.name, pid.givenName.value)
        sdClaim(OidcBirthDate.name, pid.birthDate.toString())
        sdObjClaim(OidcAssurancePlaceOfBirth.NAME) {
            sdClaim("locality", pid.birthPlace)
        }
        sdArrClaim(OidcAssuranceNationalities.name) {
            pid.nationalities.forEach { claim(it.value) }
        }
        pid.oidcAddressClaim()?.let { address ->
            sdObjClaim(OidcAddressClaim.NAME) {
                address.formatted?.let { sdClaim("formatted", it) }
                address.streetAddress?.let { sdClaim("street_address", it) }
                address.locality?.let { sdClaim("locality", it) }
                address.region?.let { sdClaim("region", it) }
                address.postalCode?.let { sdClaim("postal_code", it) }
                address.country?.let { sdClaim("country", it) }
            }
        }
        pid.portrait?.let {
            val value = when (it) {
                is PortraitImage.JPEG -> base64UrlNoPadding.encode(it.value)
                is PortraitImage.JPEG2000 -> base64UrlNoPadding.encode(it.value)
            }
            sdClaim(PortraitAttribute.name, value)
        }
        pid.familyNameBirth?.let { sdClaim(OidcAssuranceBirthFamilyName.name, it.value) }
        pid.givenNameBirth?.let { sdClaim(OidcAssuranceBirthGivenName.name, it.value) }
        pid.sex?.let { sdClaim(SexAttribute.name, it.value.toInt()) }
        pid.emailAddress?.let { sdClaim(EmailAddressAttribute.name, it) }
        pid.mobilePhoneNumber?.let { sdClaim(MobilePhoneNumberAttribute.name, it.value) }
        sdObjClaim(Attributes.AgeEqualOrOver.name) {
            pid.ageOver18?.let { sdClaim(Attributes.AgeOver18.name, it) }
        }
        pid.ageInYears?.let { sdClaim(Attributes.AgeInYears.name, it.toInt()) }
        pid.ageBirthYear?.let { sdClaim(Attributes.AgeBirthYear.name, it.value.toString()) }

        pidMetaData.personalAdministrativeNumber?.let { sdClaim(PersonalAdministrativeNumberAttribute.name, it.value) }
        sdClaim(ExpiryDateAttribute.name, pidMetaData.expiryDate.toString())
        sdClaim(IssuingAuthorityAttribute.name, pidMetaData.issuingAuthority.valueAsString())
        sdClaim(IssuingCountryAttribute.name, pidMetaData.issuingCountry.value)
        pidMetaData.documentNumber?.let { sdClaim(DocumentNumberAttribute.name, it.value) }
        pidMetaData.issuingJurisdiction?.let { sdClaim(IssuingJurisdictionAttribute.name, it) }
    }
}

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
            streetAddress = listOfNotNull(residentStreet, residentHouseNumber).joinToString(", ").takeIf { it.isNotBlank() },
        )
    } else null

private object Printer {
    val json = Json { prettyPrint = true }
    private fun JsonElement.pretty(): String = json.encodeToString(this)
    fun SdJwt<SignedJWT>.prettyPrint(): String {
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

private fun X509Certificate.containsSanDns(url: URL): Boolean =
    url.host in sanOfDNSName().getOrDefault(emptyList())

private fun X509Certificate.containsSanUri(url: URL): Boolean =
    url.toExternalForm() in sanOfUniformResourceIdentifier().getOrDefault(emptyList())
