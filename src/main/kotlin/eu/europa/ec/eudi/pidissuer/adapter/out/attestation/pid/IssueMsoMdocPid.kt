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

import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.coseAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.EncodeAttestationAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.addItemToSign
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.toFullDate
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory
import eu.europa.esig.dss.cbades.cbor.CBORUtils
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAClaimParameters
import eu.europa.esig.dss.eaa.mdoc.creation.claim.MdocEAAClaim
import eu.europa.esig.dss.spi.DSSUtils
import kotlinx.datetime.LocalDate
import java.util.Locale.ENGLISH
import kotlin.time.Clock
import kotlin.time.Duration

val PidMsoMdocScope: Scope = Scope("eu.europa.ec.eudi.pid_mso_mdoc")

private const val PID_DOCTYPE = "eu.europa.ec.eudi.pid"

private fun pidDocType(v: Int?): String =
    if (v == null)
        PID_DOCTYPE
    else
        "$PID_DOCTYPE.$v"

@Suppress("SameParameterValue")
fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

@Suppress("UNUSED")
private fun pidDomesticNameSpace(
    v: Int?,
    countryCode: String,
): MsoNameSpace =
    if (v == null)
        "$PID_DOCTYPE.$countryCode"
    else
        "$PID_DOCTYPE.$countryCode.$v"

val PidMsoMdocV1CredentialConfigurationId: CredentialConfigurationId = CredentialConfigurationId(PidMsoMdocScope.value)

internal fun pidMsoMdocV1(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = PidMsoMdocV1CredentialConfigurationId,
        docType = pidDocType(1),
        display =
            listOf(
                CredentialDisplay(
                    name = DisplayName("PID (MSO MDoc)", ENGLISH),
                ),
            ),
        claims = MsoMdocPidClaims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = PidMsoMdocScope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Pid,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

@Suppress("FunctionName")
fun IssueMsoMdocPid(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
    allocateStatus: AllocateStatus,
    issuerSigningKey: IssuerSigningKey,
): IssueMdoc<PidAttributes> {
    val configuration =
        pidMsoMdocV1(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        EncodeAttestationAttributesInMdoc(issuerSigningKey, configuration.docType) { pidAttributes(it) },
    )
}

private fun MdocEAAClaimParameters.pidAttributes(pidAttributes: PidAttributes) {
    addItemsToSign(pidAttributes.pid)
    addItemsToSign(pidAttributes.metaData)
}

private fun MdocEAAClaimParameters.addItemsToSign(pid: Pid) {
    addItemToSign(MsoMdocPidClaims.FamilyName, pid.familyName.value)
    addItemToSign(MsoMdocPidClaims.GivenName, pid.givenName.value)
    addItemToSign(MsoMdocPidClaims.BirthDate, pid.birthDate)

    val placeOfBirth =
        with(pid.placeOfBirth) {
            CBORObjectFactory.toCBORObject(
                buildMap {
                    country?.let { put("country", it.value) }
                    region?.let { put("region", it.value) }
                    locality?.let { put("locality", it.value) }
                },
            )
        }
    addItemToSign(MsoMdocPidClaims.PlaceOfBirth, placeOfBirth)

    addItemToSign(MsoMdocPidClaims.Nationality, CBORObjectFactory.toCBORObject(pid.nationalities.map { it.value }))
    pid.residentAddress?.let { addItemToSign(MsoMdocPidClaims.ResidenceAddress, it) }
    pid.residentCountry?.let { addItemToSign(MsoMdocPidClaims.ResidenceCountry, it.value) }
    pid.residentState?.let { addItemToSign(MsoMdocPidClaims.ResidenceState, it.value) }
    pid.residentCity?.let { addItemToSign(MsoMdocPidClaims.ResidenceCity, it.value) }
    pid.residentPostalCode?.let { addItemToSign(MsoMdocPidClaims.ResidencePostalCode, it.value) }
    pid.residentStreet?.let { addItemToSign(MsoMdocPidClaims.ResidenceStreet, it.value) }
    pid.residentHouseNumber?.let { addItemToSign(MsoMdocPidClaims.ResidenceHouseNumber, it) }
    pid.portrait?.let {
        val value =
            when (it) {
                is PortraitImage.JPEG -> it.value
                is PortraitImage.JPEG2000 -> it.value
            }
        addItemToSign(MsoMdocPidClaims.Portrait, value)
    }
    pid.familyNameBirth?.let { addItemToSign(MsoMdocPidClaims.FamilyNameBirth, it.value) }
    pid.givenNameBirth?.let { addItemToSign(MsoMdocPidClaims.GivenNameBirth, it.value) }
    pid.sex?.let { addItemToSign(MsoMdocPidClaims.Sex, it.value) }
    pid.emailAddress?.let { addItemToSign(MsoMdocPidClaims.EmailAddress, it) }
    pid.mobilePhoneNumber?.let { addItemToSign(MsoMdocPidClaims.MobilePhoneNumberAttribute, it.value) }
    pid.personalAdministrativeNumber?.let {
        addItemToSign(
            MsoMdocPidClaims.PersonalAdministrativeNumber,
            it.value,
        )
    }
}

private fun MdocEAAClaimParameters.addItemsToSign(metaData: PidMetaData) {
    addItemToSign(MsoMdocPidClaims.ExpiryDate, metaData.expiryDate)
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> {
            addItemToSign(MsoMdocPidClaims.IssuingAuthority, issuingAuthority.code.value)
        }

        is IssuingAuthority.AdministrativeAuthority -> {
            addItemToSign(MsoMdocPidClaims.IssuingAuthority, issuingAuthority.value)
        }
    }
    addItemToSign(MsoMdocPidClaims.IssuingCountry, metaData.issuingCountry.value)
    metaData.documentNumber?.let { addItemToSign(MsoMdocPidClaims.DocumentNumber, it.value) }
    metaData.issuingJurisdiction?.let { addItemToSign(MsoMdocPidClaims.IssuingJurisdiction, it) }
    metaData.issuanceDate?.let { addItemToSign(MsoMdocPidClaims.IssuanceDate, it) }
    metaData.attestationLegalCategory?.let {
        addItemToSign(MsoMdocPidClaims.AttestationLegalCategory, it)
    }
}
