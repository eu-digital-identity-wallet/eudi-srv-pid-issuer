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
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import kotlin.time.Duration

internal class DefaultEncodePidInCbor(
    clock: Clock,
    issuerSigningKey:
        IssuerSigningKey,
    validityDuration: Duration,
) : EncodePidInCbor {

    private val signer = MsoMdocSigner<Pair<Pid, PidMetaData>>(
        clock = clock,
        issuerSigningKey = issuerSigningKey,
        validityDuration = validityDuration,
        docType = PidMsoMdocV1.docType,
    ) { (pid, pidMetaData) ->
        addItemsToSign(pid)
        addItemsToSign(pidMetaData)
    }

    override suspend fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: ECKey,
    ): String = signer.sign(pid to pidMetaData, holderKey)
}

private fun MDocBuilder.addItemsToSign(pid: Pid) {
    addItemToSign(MsoMdocPidAttributes.GivenName, pid.givenName.value.toDataElement())
    addItemToSign(MsoMdocPidAttributes.FamilyName, pid.familyName.value.toDataElement())
    addItemToSign(MsoMdocPidAttributes.BirthDate, pid.birthDate.toKotlinLocalDate().toDataElement())
    pid.familyNameBirth?.let { addItemToSign(MsoMdocPidAttributes.FamilyNameBirth, it.value.toDataElement()) }
    pid.givenNameBirth?.let { addItemToSign(MsoMdocPidAttributes.GivenNameBirth, it.value.toDataElement()) }
    pid.gender?.let { addItemToSign(MsoMdocPidAttributes.Gender, it.value.toDataElement()) }
    pid.nationality?.let { addItemToSign(MsoMdocPidAttributes.Nationality, it.value.toDataElement()) }
    pid.ageOver18?.let { addItemToSign(MsoMdocPidAttributes.AgeOver18, it.toDataElement()) }
    pid.ageBirthYear?.let { addItemToSign(MsoMdocPidAttributes.AgeBirthYear, it.value.toDataElement()) }
    pid.ageInYears?.let { addItemToSign(MsoMdocPidAttributes.AgeInYears, it.toDataElement()) }
    pid.birthPlace?.let { addItemToSign(MsoMdocPidAttributes.BirthPlace, it.toDataElement()) }
    pid.birthCountry?.let { addItemToSign(MsoMdocPidAttributes.BirthCountry, it.value.toDataElement()) }
    pid.birthState?.let { addItemToSign(MsoMdocPidAttributes.BirthState, it.value.toDataElement()) }
    pid.birthCity?.let { addItemToSign(MsoMdocPidAttributes.BirthCity, it.value.toDataElement()) }
    pid.residentAddress?.let { addItemToSign(MsoMdocPidAttributes.ResidenceAddress, it.toDataElement()) }
    pid.residentCountry?.let { addItemToSign(MsoMdocPidAttributes.ResidenceCountry, it.value.toDataElement()) }
    pid.residentState?.let { addItemToSign(MsoMdocPidAttributes.ResidenceState, it.value.toDataElement()) }
    pid.residentCity?.let { addItemToSign(MsoMdocPidAttributes.ResidenceCity, it.value.toDataElement()) }
    pid.residentPostalCode?.let { addItemToSign(MsoMdocPidAttributes.ResidencePostalCode, it.value.toDataElement()) }
    pid.residentStreet?.let { addItemToSign(MsoMdocPidAttributes.ResidenceStreet, it.value.toDataElement()) }
    pid.residentHouseNumber?.let { addItemToSign(MsoMdocPidAttributes.ResidenceHouseNumber, it.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(metaData: PidMetaData) {
    addItemToSign(MsoMdocPidAttributes.IssuanceDate, metaData.issuanceDate.toKotlinLocalDate().toDataElement())
    addItemToSign(MsoMdocPidAttributes.ExpiryDate, metaData.expiryDate.toKotlinLocalDate().toDataElement())
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> addItemToSign(MsoMdocPidAttributes.IssuingAuthority, issuingAuthority.code.value.toDataElement())
        is IssuingAuthority.AdministrativeAuthority ->
            addItemToSign(MsoMdocPidAttributes.IssuingAuthority, issuingAuthority.value.toDataElement())
    }
    metaData.documentNumber?.let { addItemToSign(MsoMdocPidAttributes.DocumentNumber, it.value.toDataElement()) }
    metaData.administrativeNumber?.let { addItemToSign(MsoMdocPidAttributes.AdministrativeNumber, it.value.toDataElement()) }
    addItemToSign(MsoMdocPidAttributes.IssuingCountry, metaData.issuingCountry.value.toDataElement())
    metaData.issuingJurisdiction?.let { addItemToSign(MsoMdocPidAttributes.IssuingJurisdiction, it.toDataElement()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement) {
    addItemToSign(PidMsoMdocNamespace, attr.name, value)
}
