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
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.encodeAttestationAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import java.util.Locale.ENGLISH
import kotlin.time.Clock
import kotlin.time.Duration

val PidMsoMdocScope: Scope = Scope("eu.europa.ec.eudi.pid_mso_mdoc")

val PidMsoMdocNamespace: MsoNameSpace = pidNameSpace(1)

internal object MsoMdocPidClaims {
    val GivenName =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "given_name",
            mandatory = true,
            display = mapOf(ENGLISH to "Given Name(s)"),
        )
    val FamilyName =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "family_name",
            mandatory = true,
            display = mapOf(ENGLISH to "Family Name(s)"),
        )
    val BirthDate =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "birth_date",
            mandatory = true,
            display = mapOf(ENGLISH to "Birth Date"),
        )
    val FamilyNameBirth =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "family_name_birth",
            mandatory = false,
            display = mapOf(ENGLISH to "Birth Family Name(s)"),
        )
    val GivenNameBirth =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "given_name_birth",
            mandatory = false,
            display = mapOf(ENGLISH to "Birth Given Name(s)"),
        )
    val Sex =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "sex",
            mandatory = false,
            display = mapOf(ENGLISH to "Sex"),
        )
    val Nationality =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "nationality",
            mandatory = true,
            display = mapOf(ENGLISH to "Nationality"),
        )
    val IssuanceDate =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "issuance_date",
            mandatory = false,
            display = mapOf(ENGLISH to "Issuance Date"),
        )
    val ExpiryDate =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "expiry_date",
            mandatory = true,
            display = mapOf(ENGLISH to "Expiry Date"),
        )
    val IssuingAuthority =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "issuing_authority",
            mandatory = true,
            display = mapOf(ENGLISH to "Issuance Authority"),
        )
    val PlaceOfBirth =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "place_of_birth",
            mandatory = true,
            display = mapOf(ENGLISH to "Place of Birth"),
        )
    val ResidenceAddress =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_address",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Address"),
        )
    val ResidenceCountry =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_country",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Country"),
        )
    val ResidenceState =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_state",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident State"),
        )
    val ResidenceCity =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_city",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident City"),
        )
    val ResidencePostalCode =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_postal_code",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Postal Code"),
        )
    val ResidenceStreet =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_street",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Street"),
        )
    val ResidenceHouseNumber =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "resident_house_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident House Number"),
        )
    val DocumentNumber =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "document_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Document Number"),
        )
    val PersonalAdministrativeNumber =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "personal_administrative_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Personal Administrative Number"),
        )
    val IssuingCountry =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "issuing_country",
            mandatory = true,
            display = mapOf(ENGLISH to "Issuing Country"),
        )
    val IssuingJurisdiction =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "issuing_jurisdiction",
            mandatory = false,
            display = mapOf(ENGLISH to "Issuing Jurisdiction"),
        )
    val Portrait =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "portrait",
            mandatory = false,
            display = mapOf(ENGLISH to "Portrait Image"),
        )
    val EmailAddress =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "email_address",
            mandatory = false,
            display = mapOf(ENGLISH to "Email Address"),
        )
    val MobilePhoneNumberAttribute =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "mobile_phone_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Mobile Phone Number"),
        )
    val TrustAnchor =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "trust_anchor",
            mandatory = false,
            display =
                mapOf(
                    ENGLISH to "Trust Anchor",
                ),
        )
    val AttestationLegalCategory =
        ClaimDefinition(
            PidMsoMdocNamespace,
            "attestation_legal_category",
            mandatory = false,
            display =
                mapOf(
                    ENGLISH to "Attestation Legal Category",
                ),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
            FamilyName,
            GivenName,
            BirthDate,
            PlaceOfBirth,
            Nationality,
            ResidenceAddress,
            ResidenceCountry,
            ResidenceState,
            ResidenceCity,
            ResidencePostalCode,
            ResidenceStreet,
            ResidenceHouseNumber,
            PersonalAdministrativeNumber,
            Portrait,
            FamilyNameBirth,
            GivenNameBirth,
            Sex,
            EmailAddress,
            MobilePhoneNumberAttribute,
            ExpiryDate,
            IssuingAuthority,
            IssuingCountry,
            DocumentNumber,
            IssuingJurisdiction,
            IssuanceDate,
            TrustAnchor,
            AttestationLegalCategory,
        )
}

private const val PID_DOCTYPE = "eu.europa.ec.eudi.pid"

private fun pidDocType(v: Int?): String =
    if (v == null)
        PID_DOCTYPE
    else
        "$PID_DOCTYPE.$v"

@Suppress("SameParameterValue")
private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

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

val PidMsoMdocV1DocType: MsoDocType = pidDocType(1)

internal fun pidMsoMdocV1(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = PidMsoMdocV1CredentialConfigurationId,
        docType = PidMsoMdocV1DocType,
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
    val encodeAttributes = encodePidInMdoc(configuration.docType, issuerSigningKey)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        encodeAttributes,
    )
}

fun encodePidInMdoc(
    docType: MsoDocType = PidMsoMdocV1DocType,
    issuerSigningKey: IssuerSigningKey,
): EncodeAttestationAttributes<PidAttributes> =
    encodeAttestationAttributesInMdoc(docType, issuerSigningKey) { (pid, pidMetaData) ->
        addItemsToSign(pid)
        addItemsToSign(pidMetaData)
    }

private fun MDocBuilder.addItemsToSign(pid: Pid) {
    addItemToSign(MsoMdocPidClaims.FamilyName, pid.familyName.value.toDataElement())
    addItemToSign(MsoMdocPidClaims.GivenName, pid.givenName.value.toDataElement())
    addItemToSign(MsoMdocPidClaims.BirthDate, pid.birthDate.toDataElement())

    val placeOfBirth =
        with(pid.placeOfBirth) {
            buildMap {
                country?.let { put(MapKey("country"), it.value.toDataElement()) }
                region?.let { put(MapKey("region"), it.value.toDataElement()) }
                locality?.let { put(MapKey("locality"), it.value.toDataElement()) }
            }.toDataElement()
        }
    addItemToSign(MsoMdocPidClaims.PlaceOfBirth, placeOfBirth)

    addItemToSign(MsoMdocPidClaims.Nationality, pid.nationalities.map { it.value.toDataElement() }.toDataElement())
    pid.residentAddress?.let { addItemToSign(MsoMdocPidClaims.ResidenceAddress, it.toDataElement()) }
    pid.residentCountry?.let { addItemToSign(MsoMdocPidClaims.ResidenceCountry, it.value.toDataElement()) }
    pid.residentState?.let { addItemToSign(MsoMdocPidClaims.ResidenceState, it.value.toDataElement()) }
    pid.residentCity?.let { addItemToSign(MsoMdocPidClaims.ResidenceCity, it.value.toDataElement()) }
    pid.residentPostalCode?.let { addItemToSign(MsoMdocPidClaims.ResidencePostalCode, it.value.toDataElement()) }
    pid.residentStreet?.let { addItemToSign(MsoMdocPidClaims.ResidenceStreet, it.value.toDataElement()) }
    pid.residentHouseNumber?.let { addItemToSign(MsoMdocPidClaims.ResidenceHouseNumber, it.toDataElement()) }
    pid.portrait?.let {
        val value =
            when (it) {
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
    pid.personalAdministrativeNumber?.let {
        addItemToSign(
            MsoMdocPidClaims.PersonalAdministrativeNumber,
            it.value.toDataElement(),
        )
    }
}

private fun MDocBuilder.addItemsToSign(metaData: PidMetaData) {
    addItemToSign(MsoMdocPidClaims.ExpiryDate, metaData.expiryDate.toDataElement())
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> {
            addItemToSign(MsoMdocPidClaims.IssuingAuthority, issuingAuthority.code.value.toDataElement())
        }

        is IssuingAuthority.AdministrativeAuthority -> {
            addItemToSign(MsoMdocPidClaims.IssuingAuthority, issuingAuthority.value.toDataElement())
        }
    }
    addItemToSign(MsoMdocPidClaims.IssuingCountry, metaData.issuingCountry.value.toDataElement())
    metaData.documentNumber?.let { addItemToSign(MsoMdocPidClaims.DocumentNumber, it.value.toDataElement()) }
    metaData.issuingJurisdiction?.let { addItemToSign(MsoMdocPidClaims.IssuingJurisdiction, it.toDataElement()) }
    metaData.issuanceDate?.let { addItemToSign(MsoMdocPidClaims.IssuanceDate, it.toDataElement()) }
    metaData.attestationLegalCategory?.let {
        addItemToSign(
            MsoMdocPidClaims.AttestationLegalCategory,
            it.toDataElement(),
        )
    }
}

private fun MDocBuilder.addItemToSign(
    claim: ClaimDefinition,
    value: DataElement,
) {
    addItemToSign(PidMsoMdocNamespace, claim.name, value)
}
