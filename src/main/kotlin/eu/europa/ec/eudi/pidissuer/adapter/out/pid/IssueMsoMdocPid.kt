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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.toECKeyOrFail
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.allocateStatusWithPolicy
import eu.europa.ec.eudi.pidissuer.port.out.credential.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.keyAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
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
        attestationCategory = AttestationCategory.Pid,
        credentialReusePolicy = credentialReusePolicy,
    )

private val msoMdocPidLog = LoggerFactory.getLogger(IssueMsoMdocPid::class.java)

/**
 * Service for issuing PID MsoMdoc credential
 */
class IssueMsoMdocPid private constructor(
    override val configuration: MsoMdocCredentialConfiguration,
    private val getAttestationAttributes: GetAttestationAttributes<Pair<Pid, PidMetaData>>,
    private val encodePidInCbor: EncodePidInCbor,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val clock: Clock,
    override val validity: Duration,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val allocateStatus: AllocateStatus,
    private val validateProof: ValidateProof,
) : AttestationIssuer {
    init {
        require(validity.isPositive())
    }

    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        msoMdocPidLog.info("Handling issuance request ...")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val deviceKeys =
            keyAttestation.credentialKeys.value
                .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
        val (pid, pidMetaData) = getAttestationAttributes()
        val expiresAt = issuedAt + validity
        val notificationId = if (notificationsEnabled) generateNotificationId() else null
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList

        val issuedCredentials =
            deviceKeys
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val statusListToken =
                        context(allocateStatus) {
                            allocateStatusWithPolicy(expiresAt)
                        }
                    val encodedCredential =
                        encodePidInCbor(
                            pid,
                            pidMetaData,
                            deviceKey,
                            issuedAt = issuedAt,
                            expiresAt = expiresAt,
                            statusListToken,
                        ).also {
                            msoMdocPidLog.info("Issued $it")
                        }

                    storeIssuedCredential(
                        IssuedCredential(
                            format = MSO_MDOC_FORMAT,
                            type = configuration.docType,
                            issuedAt = issuedAt,
                            expiresAt = expiresAt,
                            notificationId = notificationId,
                            status = statusListToken,
                            clientStatus = clientStatus,
                            keyStorageStatus = keyStorageStatus,
                        ),
                    )

                    encodedCredential
                }.toNonEmptyListOrNull()

        checkNotNull(issuedCredentials) { "Cannot happen" }

        return CredentialResponse
            .Issued(issuedCredentials.map { JsonPrimitive(it) }, notificationId)
            .also {
                msoMdocPidLog.info("Successfully issued PIDs")
                msoMdocPidLog.debug("Issued PIDs data {}", it)
            }
    }

    companion object {
        operator fun invoke(
            getAttestationAttributes: GetAttestationAttributes<Pair<Pid, PidMetaData>>,
            encodePidInCbor: EncodePidInCbor,
            notificationsEnabled: Boolean,
            generateNotificationId: GenerateNotificationId,
            clock: Clock,
            validity: Duration,
            storeIssuedCredential: StoreIssuedCredential,
            allocateStatus: AllocateStatus,
            validateProof: ValidateProof,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
        ): IssueMsoMdocPid {
            val configuration =
                pidMsoMdocV1(encodePidInCbor.signingAlgorithm, deviceBinding, credentialReusePolicy)
            return IssueMsoMdocPid(
                configuration,
                getAttestationAttributes,
                encodePidInCbor,
                notificationsEnabled,
                generateNotificationId,
                clock,
                validity,
                storeIssuedCredential,
                allocateStatus,
                validateProof,
            )
        }
    }
}
