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
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcAddressClaim
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.pidissuer.port.out.status.GenerateStatusListToken
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

private val log = LoggerFactory.getLogger(EncodePidInSdJwtVc::class.java)

class EncodePidInSdJwtVc(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val calculateExpiresAt: TimeDependant<Instant>,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
    private val vct: SdJwtVcType,
    private val generateStatusListToken: GenerateStatusListToken?,
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
            type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
            keyID(issuerSigningKey.key.keyID)
            x509CertChain(x509CertChain)
        }
    }

    suspend fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: JWK,
    ): Either<IssueCredentialError, String> = either {
        val issuedAt = clock.instant().atZone(clock.zone)
        val expiresAt = calculateExpiresAt(issuedAt)
        val statusListToken = generateStatusListToken?.let {
            it(vct.value, expiresAt.atZone(clock.zone))
                .getOrElse { error ->
                    raise(Unexpected("Unable to generate Status List Token", error))
                }
        }
        val sdJwtSpec = selectivelyDisclosed(
            pid = pid,
            pidMetaData = pidMetaData,
            vct = vct,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderKey,
            iat = issuedAt,
            exp = expiresAt,
            nbf = calculateNotUseBefore?.let { calculate -> calculate(issuedAt) },
            statusListToken = statusListToken,
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

private val base64UrlNoPadding by lazy { Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT) }

private fun selectivelyDisclosed(
    pid: Pid,
    pidMetaData: PidMetaData,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
    holderPubKey: JWK,
    iat: ZonedDateTime,
    exp: Instant,
    nbf: Instant?,
    statusListToken: StatusListToken?,
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
        statusListToken?.let {
            objClaim("status") {
                objClaim("status_list") {
                    claim("idx", it.index.toInt())
                    claim("uri", it.statusList.toString())
                }
            }
        }

        //
        // Selectively Disclosed claims
        //
        sdClaim(SdJwtVcPidClaims.FamilyName.name, pid.familyName.value)
        sdClaim(SdJwtVcPidClaims.GivenName.name, pid.givenName.value)
        sdClaim(SdJwtVcPidClaims.BirthDate.name, pid.birthDate.toString())
        sdObjClaim(SdJwtVcPidClaims.PlaceOfBirth.attribute.name) {
            sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Locality.name, pid.birthPlace)
        }
        sdArrClaim(SdJwtVcPidClaims.Nationalities.name) {
            pid.nationalities.forEach { claim(it.value) }
        }
        pid.oidcAddressClaim()?.let { address ->
            sdObjClaim(SdJwtVcPidClaims.Address.attribute.name) {
                address.formatted?.let { sdClaim(SdJwtVcPidClaims.Address.Formatted.name, it) }
                address.streetAddress?.let { sdClaim(SdJwtVcPidClaims.Address.Street.name, it) }
                address.locality?.let { sdClaim(SdJwtVcPidClaims.Address.Locality.name, it) }
                address.region?.let { sdClaim(SdJwtVcPidClaims.Address.Region.name, it) }
                address.postalCode?.let { sdClaim(SdJwtVcPidClaims.Address.PostalCode.name, it) }
                address.country?.let { sdClaim(SdJwtVcPidClaims.Address.Country.name, it) }
            }
        }
        pidMetaData.personalAdministrativeNumber?.let { sdClaim(SdJwtVcPidClaims.PersonalAdministrativeNumber.name, it.value) }
        pid.portrait?.let {
            val value = when (it) {
                is PortraitImage.JPEG -> base64UrlNoPadding.encode(it.value)
                is PortraitImage.JPEG2000 -> base64UrlNoPadding.encode(it.value)
            }
            sdClaim(SdJwtVcPidClaims.Portrait.name, value)
        }
        pid.familyNameBirth?.let { sdClaim(SdJwtVcPidClaims.BirthFamilyName.name, it.value) }
        pid.givenNameBirth?.let { sdClaim(SdJwtVcPidClaims.BirthGivenName.name, it.value) }
        pid.sex?.let { sdClaim(SdJwtVcPidClaims.Sex.name, it.value.toInt()) }
        pid.emailAddress?.let { sdClaim(SdJwtVcPidClaims.EmailAddress.name, it) }
        pid.mobilePhoneNumber?.let { sdClaim(SdJwtVcPidClaims.MobilePhoneNumber.name, it.value) }
        sdObjClaim(SdJwtVcPidClaims.AgeEqualOrOver.attribute.name) {
            pid.ageOver18?.let { sdClaim(SdJwtVcPidClaims.AgeEqualOrOver.Over18.name, it) }
        }
        pid.ageInYears?.let { sdClaim(SdJwtVcPidClaims.AgeInYears.name, it.toInt()) }
        pid.ageBirthYear?.let { sdClaim(SdJwtVcPidClaims.AgeBirthYear.name, it.value.toString()) }

        sdClaim(SdJwtVcPidClaims.ExpiryDate.name, pidMetaData.expiryDate.toString())
        sdClaim(SdJwtVcPidClaims.IssuingAuthority.name, pidMetaData.issuingAuthority.valueAsString())
        sdClaim(SdJwtVcPidClaims.IssuingCountry.name, pidMetaData.issuingCountry.value)
        pidMetaData.documentNumber?.let { sdClaim(SdJwtVcPidClaims.DocumentNumber.name, it.value) }
        pidMetaData.issuingJurisdiction?.let { sdClaim(SdJwtVcPidClaims.IssuingJurisdiction.name, it) }
        pidMetaData.issuanceDate?.let { sdClaim(SdJwtVcPidClaims.IssuanceDate.name, it.toString()) }
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
