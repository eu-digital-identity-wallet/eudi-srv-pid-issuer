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
    addItemToSign(GivenNameAttribute, pid.givenName.value.toDataElement())
    addItemToSign(FamilyNameAttribute, pid.familyName.value.toDataElement())
    addItemToSign(BirthDateAttribute, pid.birthDate.toKotlinLocalDate().toDataElement())
    pid.familyNameBirth?.let { addItemToSign(FamilyNameBirthAttribute, it.value.toDataElement()) }
    pid.givenNameBirth?.let { addItemToSign(GivenNameBirthAttribute, it.value.toDataElement()) }
    pid.gender?.let { addItemToSign(GenderAttribute, it.value.toDataElement()) }
    addItemToSign(NationalityAttribute, pid.nationalities.map { it.value.toDataElement() }.toDataElement())
    pid.ageOver18?.let { addItemToSign(AgeOver18Attribute, it.toDataElement()) }
    pid.ageBirthYear?.let { addItemToSign(AgeBirthYearAttribute, it.value.toDataElement()) }
    pid.ageInYears?.let { addItemToSign(AgeInYearsAttribute, it.toDataElement()) }
    addItemToSign(BirthPlaceAttribute, pid.birthPlace.toDataElement())
    pid.residentAddress?.let { addItemToSign(ResidenceAddressAttribute, it.toDataElement()) }
    pid.residentCountry?.let { addItemToSign(ResidenceCountryAttribute, it.value.toDataElement()) }
    pid.residentState?.let { addItemToSign(ResidenceStateAttribute, it.value.toDataElement()) }
    pid.residentCity?.let { addItemToSign(ResidenceCityAttribute, it.value.toDataElement()) }
    pid.residentPostalCode?.let { addItemToSign(ResidencePostalCodeAttribute, it.value.toDataElement()) }
    pid.residentStreet?.let { addItemToSign(ResidenceStreetAttribute, it.value.toDataElement()) }
    pid.residentHouseNumber?.let { addItemToSign(ResidenceHouseNumberAttribute, it.toDataElement()) }
}

private fun MDocBuilder.addItemsToSign(metaData: PidMetaData) {
    metaData.issuanceDate?.let { addItemToSign(IssuanceDateAttribute, it.toKotlinLocalDate().toDataElement()) }
    addItemToSign(ExpiryDateAttribute, metaData.expiryDate.toKotlinLocalDate().toDataElement())
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> addItemToSign(IssuingAuthorityAttribute, issuingAuthority.code.value.toDataElement())
        is IssuingAuthority.AdministrativeAuthority ->
            addItemToSign(IssuingAuthorityAttribute, issuingAuthority.value.toDataElement())
    }
    metaData.documentNumber?.let { addItemToSign(DocumentNumberAttribute, it.value.toDataElement()) }
    metaData.personalAdministrativeNumber?.let { addItemToSign(AdministrativeNumberAttribute, it.value.toDataElement()) }
    addItemToSign(IssuingCountryAttribute, metaData.issuingCountry.value.toDataElement())
    metaData.issuingJurisdiction?.let { addItemToSign(IssuingJurisdictionAttribute, it.toDataElement()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement) {
    addItemToSign(PidMsoMdocNamespace, attr.name, value)
}
