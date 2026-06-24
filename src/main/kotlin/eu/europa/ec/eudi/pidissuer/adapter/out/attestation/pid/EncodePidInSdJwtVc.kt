/*
 * Copyright (c) 2023-2026 European Commission
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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.OidcAddressClaim
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.SdJwtVcSerialization
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.encodeAttestationAttributesInSdJwtVc
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObject
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.io.encoding.Base64
import kotlin.time.Instant

fun encodePidInSdJwtVc(
    sdJwtVcSerialization: SdJwtVcSerialization = SdJwtVcSerialization.Compact,
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
): EncodeAttestationAttributes<PidAttributes> =
    encodeAttestationAttributesInSdJwtVc(
        sdJwtVcSerialization,
        digestsHashAlgorithm,
        issuerSigningKey,
        vct,
        issuer = credentialIssuerId,
    ) { sdJwtSpec(it) }

fun SdJwtObjectBuilder.sdJwtSpec(attributes: PidAttributes) {
    val (pid, pidMetaData) = attributes
    //
    // Selectively Disclosed claims
    //
    sdClaim(SdJwtVcPidClaims.FamilyName.name, pid.familyName.value)
    sdClaim(SdJwtVcPidClaims.GivenName.name, pid.givenName.value)
    sdClaim(SdJwtVcPidClaims.BirthDate.name, pid.birthDate.toString())
    with(pid.placeOfBirth) {
        sdObjClaim(SdJwtVcPidClaims.PlaceOfBirth.attribute.name) {
            country?.let { sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Country.name, it.value) }
            region?.let { sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Region.name, it.value) }
            locality?.let { sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Locality.name, it.value) }
        }
    }
    sdArrClaim(SdJwtVcPidClaims.Nationalities.name) {
        pid.nationalities.forEach { sdClaim(it.value) }
    }
    pid.oidcAddressClaim()?.let { address ->
        sdObjClaim(SdJwtVcPidClaims.Address.attribute.name) {
            address.formatted?.let { sdClaim(SdJwtVcPidClaims.Address.Formatted.name, it) }
            address.houseNumber?.let { sdClaim(SdJwtVcPidClaims.Address.HouseNumber.name, it) }
            address.streetAddress?.let { sdClaim(SdJwtVcPidClaims.Address.Street.name, it) }
            address.locality?.let { sdClaim(SdJwtVcPidClaims.Address.Locality.name, it) }
            address.region?.let { sdClaim(SdJwtVcPidClaims.Address.Region.name, it) }
            address.postalCode?.let { sdClaim(SdJwtVcPidClaims.Address.PostalCode.name, it) }
            address.country?.let { sdClaim(SdJwtVcPidClaims.Address.Country.name, it) }
        }
    }
    pid.personalAdministrativeNumber?.let { sdClaim(SdJwtVcPidClaims.PersonalAdministrativeNumber.name, it.value) }
    pid.portrait?.let {
        val encodedBytes =
            when (it) {
                is PortraitImage.JPEG -> Base64.encode(it.value)
                is PortraitImage.JPEG2000 -> Base64.encode(it.value)
            }
        val url = "data:image/jpeg;base64,$encodedBytes"
        sdClaim(SdJwtVcPidClaims.Picture.name, url)
    }
    pid.familyNameBirth?.let { sdClaim(SdJwtVcPidClaims.BirthFamilyName.name, it.value) }
    pid.givenNameBirth?.let { sdClaim(SdJwtVcPidClaims.BirthGivenName.name, it.value) }
    pid.sex?.let { sdClaim(SdJwtVcPidClaims.Sex.name, it.value.toInt()) }
    pid.emailAddress?.let { sdClaim(SdJwtVcPidClaims.Email.name, it) }
    pid.mobilePhoneNumber?.let { sdClaim(SdJwtVcPidClaims.PhoneNumber.name, it.value) }

    sdClaim(SdJwtVcPidClaims.DateOfExpiry.name, pidMetaData.expiryDate.toString())
    sdClaim(SdJwtVcPidClaims.IssuingAuthority.name, pidMetaData.issuingAuthority.valueAsString())
    sdClaim(SdJwtVcPidClaims.IssuingCountry.name, pidMetaData.issuingCountry.value)
    pidMetaData.documentNumber?.let { sdClaim(SdJwtVcPidClaims.DocumentNumber.name, it.value) }
    pidMetaData.issuingJurisdiction?.let { sdClaim(SdJwtVcPidClaims.IssuingJurisdiction.name, it) }
    pidMetaData.issuanceDate?.let { sdClaim(SdJwtVcPidClaims.DateOfIssuance.name, it.toString()) }
    pidMetaData.attestationLegalCategory?.let { sdClaim(SdJwtVcPidClaims.AttestationLegalCategory.name, it) }
}

private fun Pid.oidcAddressClaim(): OidcAddressClaim? =
    if (
        residentHouseNumber != null || residentStreet != null || residentPostalCode != null ||
        residentCity != null || residentState != null || residentCountry != null ||
        residentAddress != null
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
    } else {
        null
    }

private object Printer {
    val json = Json { prettyPrint = true }

    private fun JsonElement.pretty(): String = json.encodeToString(this)

    fun SdJwt<SignedJWT>.prettyPrint(): String {
        var str = "\nSD-JWT with ${disclosures.size} disclosures\n"
        disclosures.forEach { d ->
            val kind =
                when (d) {
                    is Disclosure.ArrayElement -> "\t - ArrayEntry ${d.claim().value().pretty()}"
                    is Disclosure.ObjectProperty -> "\t - ObjectProperty ${d.claim().first} = ${d.claim().second}"
                }
            str += kind + "\n"
        }
        str += "SD-JWT payload\n"
        str +=
            json.parseToJsonElement(jwt.jwtClaimsSet.toString()).run {
                json.encodeToString(this)
            }
        return str
    }
}
