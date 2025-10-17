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
import arrow.core.NonEmptySet
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.jwkExtensions
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.util.Locale.ENGLISH
import kotlin.time.Duration

val PidMsoMdocScope: Scope = Scope("eu.europa.ec.eudi.pid_mso_mdoc")

val PidMsoMdocNamespace: MsoNameSpace = pidNameSpace(1)

internal object MsoMdocPidClaims {

    val GivenName = ClaimDefinition(
        PidMsoMdocNamespace,
        "given_name",
        mandatory = true,
        display = mapOf(ENGLISH to "Given Name(s)"),
    )
    val FamilyName = ClaimDefinition(
        PidMsoMdocNamespace,
        "family_name",
        mandatory = true,
        display = mapOf(ENGLISH to "Family Name(s)"),
    )
    val BirthDate = ClaimDefinition(
        PidMsoMdocNamespace,
        "birth_date",
        mandatory = true,
        display = mapOf(ENGLISH to "Birth Date"),
    )
    val FamilyNameBirth = ClaimDefinition(
        PidMsoMdocNamespace,
        "family_name_birth",
        mandatory = false,
        display = mapOf(ENGLISH to "Birth Family Name(s)"),
    )
    val GivenNameBirth = ClaimDefinition(
        PidMsoMdocNamespace,
        "given_name_birth",
        mandatory = false,
        display = mapOf(ENGLISH to "Birth Given Name(s)"),
    )
    val Sex = ClaimDefinition(
        PidMsoMdocNamespace,
        "sex",
        mandatory = false,
        display = mapOf(ENGLISH to "Sex"),
    )
    val Nationality = ClaimDefinition(
        PidMsoMdocNamespace,
        "nationality",
        mandatory = true,
        display = mapOf(ENGLISH to "Nationality"),
    )
    val IssuanceDate = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuance_date",
        mandatory = false,
        display = mapOf(ENGLISH to "Issuance Date"),
    )
    val ExpiryDate = ClaimDefinition(
        PidMsoMdocNamespace,
        "expiry_date",
        mandatory = true,
        display = mapOf(ENGLISH to "Expiry Date"),
    )
    val IssuingAuthority = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuing_authority",
        mandatory = true,
        display = mapOf(ENGLISH to "Issuance Authority"),
    )
    val BirthPlace = ClaimDefinition(
        PidMsoMdocNamespace,
        "birth_place",
        mandatory = true,
        display = mapOf(ENGLISH to "Birth Place"),
    )
    val ResidenceAddress = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_address",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident Address"),
    )
    val ResidenceCountry = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_country",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident Country"),
    )
    val ResidenceState = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_state",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident State"),
    )
    val ResidenceCity = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_city",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident City"),
    )
    val ResidencePostalCode = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_postal_code",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident Postal Code"),
    )
    val ResidenceStreet = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_street",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident Street"),
    )
    val ResidenceHouseNumber = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_house_number",
        mandatory = false,
        display = mapOf(ENGLISH to "Resident House Number"),
    )
    val DocumentNumber = ClaimDefinition(
        PidMsoMdocNamespace,
        "document_number",
        mandatory = false,
        display = mapOf(ENGLISH to "Document Number"),
    )
    val PersonalAdministrativeNumber = ClaimDefinition(
        PidMsoMdocNamespace,
        "personal_administrative_number",
        mandatory = false,
        display = mapOf(ENGLISH to "Personal Administrative Number"),
    )
    val IssuingCountry = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuing_country",
        mandatory = true,
        display = mapOf(ENGLISH to "Issuing Country"),
    )
    val IssuingJurisdiction = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuing_jurisdiction",
        mandatory = false,
        display = mapOf(ENGLISH to "Issuing Jurisdiction"),
    )
    val Portrait = ClaimDefinition(
        PidMsoMdocNamespace,
        "portrait",
        mandatory = false,
        display = mapOf(ENGLISH to "Portrait Image"),
    )
    val EmailAddress = ClaimDefinition(
        PidMsoMdocNamespace,
        "email_address",
        mandatory = false,
        display = mapOf(ENGLISH to "Email Address"),
    )
    val MobilePhoneNumberAttribute = ClaimDefinition(
        PidMsoMdocNamespace,
        "mobile_phone_number",
        mandatory = false,
        display = mapOf(ENGLISH to "Mobile Phone Number"),
    )
    val TrustAnchor = ClaimDefinition(
        PidMsoMdocNamespace,
        "trust_anchor",
        mandatory = false,
        display = mapOf(
            ENGLISH to "Trust Anchor",
        ),
    )

    fun all(): List<ClaimDefinition> = listOf(
        FamilyName,
        GivenName,
        BirthDate,
        BirthPlace,
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
    )
}

private const val PID_DOCTYPE = "eu.europa.ec.eudi.pid"

private fun pidDocType(v: Int?): String =
    if (v == null) PID_DOCTYPE
    else "$PID_DOCTYPE.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

val PidMsoMdocV1CredentialConfigurationId: CredentialConfigurationId = CredentialConfigurationId(PidMsoMdocScope.value)

val PidMsoMdocV1DocType: MsoDocType = pidDocType(1)

internal fun pidMsoMdocV1(
    proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    keyAttestationRequirement: KeyAttestationRequirement,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = PidMsoMdocV1CredentialConfigurationId,
        docType = PidMsoMdocV1DocType,
        display = listOf(
            CredentialDisplay(
                name = DisplayName("PID (MSO MDoc)", ENGLISH),
            ),
        ),
        claims = MsoMdocPidClaims.all(),
        cryptographicBindingMethodsSupported = setOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = null,
        scope = PidMsoMdocScope,
        proofTypesSupported = ProofTypesSupported(
            ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement),
        ),
        policy = MsoMdocPolicy(oneTimeUse = true),
    )

/**
 * Service for issuing PID MsoMdoc credential
 */
internal class IssueMsoMdocPid(
    private val validateProofs: ValidateProofs,
    private val getPidData: GetPidData,
    private val encodePidInCbor: EncodePidInCbor,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val clock: Clock,
    private val validityDuration: Duration,
    private val storeIssuedCredentials: StoreIssuedCredentials,
    jwtProofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    override val keyAttestationRequirement: KeyAttestationRequirement = KeyAttestationRequirement.NotRequired,
) : IssueSpecificCredential {

    private val log = LoggerFactory.getLogger(IssueMsoMdocPid::class.java)

    override val supportedCredential: MsoMdocCredentialConfiguration =
        pidMsoMdocV1(jwtProofsSupportedSigningAlgorithms, keyAttestationRequirement)

    override val publicKey: JWK? = null

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Handling issuance request ...")
        val holderPubKeys = with(jwkExtensions()) {
            validateProofs(request.unvalidatedProofs, supportedCredential, clock.now())
                .bind()
                .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
        }

        val pidData = getPidData(authorizationContext)
        val (pid, pidMetaData) = pidData.bind()

        val issuedAt = clock.now()
        val expiresAt = issuedAt + validityDuration

        val issuedCredentials = holderPubKeys.parMap(Dispatchers.Default, 4) { holderKey ->
            encodePidInCbor(pid, pidMetaData, holderKey, issuedAt = issuedAt, expiresAt = expiresAt)
                .also {
                    log.info("Issued $it")
                }
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) {
            IssueCredentialError.Unexpected("Unable to issue PID")
        }

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null

        storeIssuedCredentials(
            IssuedCredentials(
                format = MSO_MDOC_FORMAT,
                type = supportedCredential.docType,
                holder = with(pid) {
                    "${familyName.value} ${givenName.value}"
                },
                holderPublicKeys = holderPubKeys,
                issuedAt = issuedAt,
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(issuedCredentials.map { JsonPrimitive(it) }, notificationId)
            .also {
                log.info("Successfully issued PIDs")
                log.debug("Issued PIDs data {}", it)
            }
    }
}
