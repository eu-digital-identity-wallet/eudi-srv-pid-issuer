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

import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.MsoMdocSigner
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import kotlin.time.Instant

internal class DefaultEncodePidInCbor(issuerSigningKey: IssuerSigningKey) : EncodePidInCbor {

    private val signer = MsoMdocSigner<Pair<Pid, PidMetaData>>(
        issuerSigningKey = issuerSigningKey,
        docType = PidMsoMdocV1DocType,
    ) { (pid, pidMetaData) ->
        addItemsToSign(pid)
        addItemsToSign(pidMetaData)
    }

    override suspend fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: ECKey,
        issuedAt: Instant,
        expiresAt: Instant,
    ): String = signer.sign(pid to pidMetaData, holderKey, issuedAt = issuedAt, expiresAt = expiresAt)
}

private fun MDocBuilder.addItemsToSign(pid: Pid) {
    addItemToSign(MsoMdocPidClaims.FamilyName, pid.familyName.value.toDataElement())
    addItemToSign(MsoMdocPidClaims.GivenName, pid.givenName.value.toDataElement())
    addItemToSign(MsoMdocPidClaims.BirthDate, pid.birthDate.toDataElement())
    val birthPlace = pid.birthPlace?.let { birthPlace ->
        listOfNotNull(birthPlace.locality?.value, birthPlace.region?.value, birthPlace.country?.value)
            .joinToString(separator = ", ")
            .takeIf { it.isNotBlank() }
    } ?: "Not known"
    addItemToSign(MsoMdocPidClaims.BirthPlace, birthPlace.toDataElement())
    addItemToSign(MsoMdocPidClaims.Nationality, pid.nationalities.map { it.value.toDataElement() }.toDataElement())
    pid.residentAddress?.let { addItemToSign(MsoMdocPidClaims.ResidenceAddress, it.toDataElement()) }
    pid.residentCountry?.let { addItemToSign(MsoMdocPidClaims.ResidenceCountry, it.value.toDataElement()) }
    pid.residentState?.let { addItemToSign(MsoMdocPidClaims.ResidenceState, it.value.toDataElement()) }
    pid.residentCity?.let { addItemToSign(MsoMdocPidClaims.ResidenceCity, it.value.toDataElement()) }
    pid.residentPostalCode?.let { addItemToSign(MsoMdocPidClaims.ResidencePostalCode, it.value.toDataElement()) }
    pid.residentStreet?.let { addItemToSign(MsoMdocPidClaims.ResidenceStreet, it.value.toDataElement()) }
    pid.residentHouseNumber?.let { addItemToSign(MsoMdocPidClaims.ResidenceHouseNumber, it.toDataElement()) }
    pid.portrait?.let {
        val value = when (it) {
            is PortraitImage.JPEG -> it.value
            is PortraitImage.JPEG2000 -> it.value
        }
        addItemToSign(MsoMdocPidClaims.Portrait, value.toDataElement())
    }
    pid.familyNameBirth?.let { addItemToSign(MsoMdocPidClaims.FamilyNameBirth, it.value.toDataElement()) }
    pid.givenNameBirth?.let { addItemToSign(MsoMdocPidClaims.GivenNameBirth, it.value.toDataElement()) }
    pid.sex?.let { addItemToSign(MsoMdocPidClaims.Sex, it.value.toDataElement()) }
    pid.emailAddress?.let { addItemToSign(MsoMdocPidClaims.EmailAddress, it.toDataElement()) }
    pid.mobilePhoneNumber?.let { addItemToSign(MsoMdocPidClaims.MobilePhoneNumberAttribute, it.value.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(metaData: PidMetaData) {
    metaData.personalAdministrativeNumber?.let { addItemToSign(MsoMdocPidClaims.PersonalAdministrativeNumber, it.value.toDataElement()) }
    addItemToSign(MsoMdocPidClaims.ExpiryDate, metaData.expiryDate.toDataElement())
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState ->
            addItemToSign(MsoMdocPidClaims.IssuingAuthority, issuingAuthority.code.value.toDataElement())
        is IssuingAuthority.AdministrativeAuthority ->
            addItemToSign(MsoMdocPidClaims.IssuingAuthority, issuingAuthority.value.toDataElement())
    }
    addItemToSign(MsoMdocPidClaims.IssuingCountry, metaData.issuingCountry.value.toDataElement())
    metaData.documentNumber?.let { addItemToSign(MsoMdocPidClaims.DocumentNumber, it.value.toDataElement()) }
    metaData.issuingJurisdiction?.let { addItemToSign(MsoMdocPidClaims.IssuingJurisdiction, it.toDataElement()) }
    metaData.issuanceDate?.let { addItemToSign(MsoMdocPidClaims.IssuanceDate, it.toDataElement()) }
}

private fun MDocBuilder.addItemToSign(claim: ClaimDefinition, value: DataElement) {
    addItemToSign(PidMsoMdocNamespace, claim.name, value)
}
