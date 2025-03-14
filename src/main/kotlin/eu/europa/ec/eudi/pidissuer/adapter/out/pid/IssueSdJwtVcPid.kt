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
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.*
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.status.GenerateStatusListToken
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.util.*

val PidSdJwtVcScope: Scope = Scope("eu.europa.ec.eudi.pid_vc_sd_jwt")

internal object SdJwtVcPidAgeEqualOrOver : IsAttribute {
    const val NAME = "age_equal_or_over"

    override val attribute: ClaimDefinition
        get() = ClaimDefinition(
            path = ClaimPath.claim(NAME),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Equal or Over"),
            nested = listOf(Over18),
        )

    val Over18 = ClaimDefinition(
        path = ClaimPath.claim(NAME).claim("18"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Over 18"),
    )
}

internal object SdJwtVcPidClaims {

    val FamilyName = OidcFamilyName
    val GivenName = OidcGivenName
    val BirthDate = OidcBirthDate
    val BirthFamilyName = OidcAssuranceBirthFamilyName
    val BirthGivenName = OidcAssuranceBirthGivenName
    val PlaceOfBirth = OidcAssurancePlaceOfBirth
    val Address = OidcAddressClaim
    val Sex = ClaimDefinition(
        path = ClaimPath.claim("sex"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Sex"),
    )
    val Nationalities = OidcAssuranceNationalities
    val AgeBirthYear = ClaimDefinition(
        path = ClaimPath.claim("age_birth_year"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age Year of Birth"),
    )
    val AgeEqualOrOver = SdJwtVcPidAgeEqualOrOver
    val AgeInYears = ClaimDefinition(
        path = ClaimPath.claim("age_in_years"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age in Years"),
    )
    val IssuingAuthority = ClaimDefinition(
        path = ClaimPath.claim("issuing_authority"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuing Authority"),
    )
    val DocumentNumber = ClaimDefinition(
        path = ClaimPath.claim("document_number"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Document Number"),
    )
    val PersonalAdministrativeNumber = ClaimDefinition(
        path = ClaimPath.claim("personal_administrative_number"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Personal Administrative Number"),
    )
    val IssuingCountry = ClaimDefinition(
        path = ClaimPath.claim("issuing_country"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Issuing Country"),
    )
    val IssuingJurisdiction = ClaimDefinition(
        path = ClaimPath.claim("issuing_jurisdiction"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Issuing Jurisdiction"),
    )
    val EmailAddress = ClaimDefinition(
        path = ClaimPath.claim("email_address"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Email Address"),
    )
    val MobilePhoneNumber = ClaimDefinition(
        path = ClaimPath.claim("mobile_phone_number"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Mobile Phone Number"),
    )
    val Portrait = ClaimDefinition(
        path = ClaimPath.claim("portrait"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Portrait Image"),
    )
    val ExpiryDate = ClaimDefinition(
        path = ClaimPath.claim("expiry_date"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Expiry Date"),
    )
    val IssuanceDate = ClaimDefinition(
        path = ClaimPath.claim("issuance_date"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Issuance Date"),
    )
    val TrustAnchor = ClaimDefinition(
        path = ClaimPath.claim("trust_anchor"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Trust Anchor",
        ),
    )

    fun all(): List<ClaimDefinition> = listOf(
        FamilyName,
        GivenName,
        BirthDate,
        PlaceOfBirth.attribute,
        Nationalities,
        Address.attribute,
        PersonalAdministrativeNumber,
        Portrait,
        BirthFamilyName,
        BirthGivenName,
        Sex,
        EmailAddress,
        MobilePhoneNumber,
        ExpiryDate,
        IssuingAuthority,
        IssuingCountry,
        DocumentNumber,
        IssuingJurisdiction,
        IssuanceDate,
        AgeEqualOrOver.attribute,
        AgeInYears,
        AgeBirthYear,
        TrustAnchor,
    )
}

private fun pidDocType(version: Int): String = "urn:eu.europa.ec.eudi:pid:$version"

fun pidSdJwtVcV1(signingAlgorithm: JWSAlgorithm): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSdJwtVcScope.value),
        type = SdJwtVcType(pidDocType(1)),
        display = pidDisplay,
        claims = SdJwtVcPidClaims.all(),
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        scope = PidSdJwtVcScope,
        proofTypesSupported = ProofTypesSupported(
            nonEmptySetOf(
                ProofType.Jwt(
                    nonEmptySetOf(
                        JWSAlgorithm.RS256,
                        JWSAlgorithm.ES256,
                    ),
                    KeyAttestation.NotRequired,
                ),
            ),
        ),
    )

typealias TimeDependant<F> = (ZonedDateTime) -> F

private val log = LoggerFactory.getLogger(IssueSdJwtVcPid::class.java)

/**
 * Service for issuing PID SD JWT credential
 */
internal class IssueSdJwtVcPid(
    private val validateProofs: ValidateProofs,
    credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val getPidData: GetPidData,
    calculateExpiresAt: TimeDependant<Instant>,
    calculateNotUseBefore: TimeDependant<Instant>?,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredentials: StoreIssuedCredentials,
    private val generateStatusListToken: GenerateStatusListToken?,
) : IssueSpecificCredential {

    override val supportedCredential: SdJwtVcCredentialConfiguration = pidSdJwtVcV1(issuerSigningKey.signingAlgorithm)
    override val publicKey: JWK
        get() = issuerSigningKey.key.toPublicJWK()

    private val encodePidInSdJwt = EncodePidInSdJwtVc(
        credentialIssuerId,
        clock,
        hashAlgorithm,
        issuerSigningKey,
        calculateExpiresAt,
        calculateNotUseBefore,
        supportedCredential.type,
        generateStatusListToken,
    )

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = coroutineScope {
        log.info("Handling issuance request ...")
        either {
            val holderPubKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.instant()).bind()
            val pidData = async { getPidData(authorizationContext) }
            val (pid, pidMetaData) = pidData.await().bind()
            val notificationId =
                if (notificationsEnabled) generateNotificationId()
                else null
            val issuedCredentials = holderPubKeys.map { holderPubKey ->
                val sdJwt = encodePidInSdJwt.invoke(pid, pidMetaData, holderPubKey).bind()
                sdJwt to holderPubKey.toPublicJWK()
            }.toNonEmptyListOrNull()
            ensureNotNull(issuedCredentials) {
                IssueCredentialError.Unexpected("Unable to issue PID")
            }

            storeIssuedCredentials(
                IssuedCredentials(
                    format = SD_JWT_VC_FORMAT,
                    type = supportedCredential.type.value,
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
