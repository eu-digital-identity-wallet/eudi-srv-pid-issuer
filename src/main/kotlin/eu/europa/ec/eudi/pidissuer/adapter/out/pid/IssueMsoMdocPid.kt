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
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
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
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.util.*

val PidMsoMdocScope: Scope = Scope("eu.europa.ec.eudi.pid_mso_mdoc")

val PidMsoMdocNamespace: MsoNameSpace = pidNameSpace(1)

internal object MsoMdocPidClaims {

    val GivenName = ClaimDefinition(
        PidMsoMdocNamespace,
        "given_name",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Given Name(s)"),
    )
    val FamilyName = ClaimDefinition(
        PidMsoMdocNamespace,
        "family_name",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Family Name(s)"),
    )
    val BirthDate = ClaimDefinition(
        PidMsoMdocNamespace,
        "birth_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Birth Date"),
    )
    val FamilyNameBirth = ClaimDefinition(
        PidMsoMdocNamespace,
        "family_name_birth",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Birth Family Name(s)"),
    )
    val GivenNameBirth = ClaimDefinition(
        PidMsoMdocNamespace,
        "given_name_birth",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Birth Given Name(s)"),
    )
    val Sex = ClaimDefinition(
        PidMsoMdocNamespace,
        "sex",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Sex"),
    )
    val AgeOver18 = ClaimDefinition(
        PidMsoMdocNamespace,
        "age_over_18",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Over 18"),
    )
    val AgeBirthYear = ClaimDefinition(
        PidMsoMdocNamespace,
        "age_birth_year",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Year of Birth"),
    )
    val AgeInYears = ClaimDefinition(
        PidMsoMdocNamespace,
        "age_in_years",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age in Years"),
    )
    val Nationality = ClaimDefinition(
        PidMsoMdocNamespace,
        "nationality",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Nationality"),
    )
    val IssuanceDate = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuance_date",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Issuance Date"),
    )
    val ExpiryDate = ClaimDefinition(
        PidMsoMdocNamespace,
        "expiry_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Expiry Date"),
    )
    val IssuingAuthority = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuing_authority",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuance Authority"),
    )
    val BirthPlace = ClaimDefinition(
        PidMsoMdocNamespace,
        "birth_place",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Birth Place"),
    )
    val ResidenceAddress = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_address",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident Address"),
    )
    val ResidenceCountry = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_country",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident Country"),
    )
    val ResidenceState = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_state",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident State"),
    )
    val ResidenceCity = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_city",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident City"),
    )
    val ResidencePostalCode = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_postal_code",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident Postal Code"),
    )
    val ResidenceStreet = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_street",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident Street"),
    )
    val ResidenceHouseNumber = ClaimDefinition(
        PidMsoMdocNamespace,
        "resident_house_number",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Resident House Number"),
    )
    val DocumentNumber = ClaimDefinition(
        PidMsoMdocNamespace,
        "document_number",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Document Number"),
    )
    val PersonalAdministrativeNumber = ClaimDefinition(
        PidMsoMdocNamespace,
        "personal_administrative_number",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Personal Administrative Number"),
    )
    val IssuingCountry = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuing_country",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuing Country"),
    )
    val IssuingJurisdiction = ClaimDefinition(
        PidMsoMdocNamespace,
        "issuing_jurisdiction",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Issuing Jurisdiction"),
    )
    val Portrait = ClaimDefinition(
        PidMsoMdocNamespace,
        "portrait",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Portrait Image"),
    )
    val EmailAddress = ClaimDefinition(
        PidMsoMdocNamespace,
        "email_address",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Email Address"),
    )
    val MobilePhoneNumberAttribute = ClaimDefinition(
        PidMsoMdocNamespace,
        "mobile_phone_number",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Mobile Phone Number"),
    )
    val TrustAnchor = ClaimDefinition(
        PidMsoMdocNamespace,
        "trust_anchor",
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Trust Anchor",
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
        AgeOver18,
        AgeInYears,
        AgeBirthYear,
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

val PidMsoMdocV1: MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(PidMsoMdocScope.value),
        docType = pidDocType(1),
        display = pidDisplay,
        claims = MsoMdocPidClaims.all(),
        cryptographicBindingMethodsSupported = emptySet(),
        credentialSigningAlgorithmsSupported = emptySet(),
        scope = PidMsoMdocScope,
        proofTypesSupported = ProofTypesSupported(
            nonEmptySetOf(
                ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.ES256), KeyAttestation.NotRequired),
            ),
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
    private val storeIssuedCredentials: StoreIssuedCredentials,
) : IssueSpecificCredential {

    private val log = LoggerFactory.getLogger(IssueMsoMdocPid::class.java)

    override val supportedCredential: MsoMdocCredentialConfiguration
        get() = PidMsoMdocV1
    override val publicKey: JWK? = null

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = coroutineScope {
        either {
            log.info("Handling issuance request ...")
            val holderPubKeys = with(jwkExtensions()) {
                validateProofs(request.unvalidatedProofs, supportedCredential, clock.instant())
                    .bind()
                    .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
            }

            val pidData = async { getPidData(authorizationContext) }
            val notificationId =
                if (notificationsEnabled) generateNotificationId()
                else null

            val (pid, pidMetaData) = pidData.await().bind()
            val issuedCredentials = holderPubKeys.map { holderKey ->
                val cbor = encodePidInCbor(pid, pidMetaData, holderKey).also {
                    log.info("Issued $it")
                }
                cbor to holderKey.toPublicJWK()
            }.toNonEmptyListOrNull()
            ensureNotNull(issuedCredentials) {
                IssueCredentialError.Unexpected("Unable to issue PID")
            }

            storeIssuedCredentials(
                IssuedCredentials(
                    format = MSO_MDOC_FORMAT,
                    type = supportedCredential.docType,
                    holder = with(pid) {
                        "${familyName.value} ${givenName.value}"
                    },
                    holderPublicKeys = issuedCredentials.map { it.second },
                    issuedAt = clock.instant(),
                    notificationId = notificationId,
                ),
            )

            CredentialResponse.Issued(issuedCredentials.map { JsonPrimitive(it.first) }, notificationId)
                .also {
                    log.info("Successfully issued PIDs")
                    log.debug("Issued PIDs data {}", it)
                }
        }
    }
}
