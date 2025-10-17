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

import arrow.core.*
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.*
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import eu.europa.ec.eudi.pidissuer.port.out.status.GenerateStatusListToken
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.time.Instant

val PidSdJwtVcScope: Scope = Scope("eu.europa.ec.eudi.pid_vc_sd_jwt")

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
    val Email = ClaimDefinition(
        path = ClaimPath.claim("email"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Email Address"),
    )
    val PhoneNumber = ClaimDefinition(
        path = ClaimPath.claim("phone_number"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Mobile Phone Number"),
    )
    val Picture = ClaimDefinition(
        path = ClaimPath.claim("picture"),
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Portrait Image"),
    )
    val DateOfExpiry = ClaimDefinition(
        path = ClaimPath.claim("date_of_expiry"),
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Expiry Date"),
    )
    val DateOfIssuance = ClaimDefinition(
        path = ClaimPath.claim("date_of_issuance"),
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
        Picture,
        BirthFamilyName,
        BirthGivenName,
        Sex,
        Email,
        PhoneNumber,
        DateOfExpiry,
        IssuingAuthority,
        IssuingCountry,
        DocumentNumber,
        IssuingJurisdiction,
        DateOfIssuance,
        TrustAnchor,
    )
}

private fun pidDocType(version: Int): String = "urn:eudi:pid:$version"

internal val SdJwtVcPidVct: SdJwtVcType = SdJwtVcType(pidDocType(1))

internal val SdJwtVcPidCredentialConfigurationId: CredentialConfigurationId = CredentialConfigurationId(PidSdJwtVcScope.value)

fun pidSdJwtVcV1(
    signingAlgorithm: JWSAlgorithm,
    proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    keyAttestationRequirement: KeyAttestationRequirement,
): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = SdJwtVcPidCredentialConfigurationId,
        type = SdJwtVcPidVct,
        display = listOf(
            CredentialDisplay(
                name = DisplayName("PID (SD-JWT VC Compact)", Locale.ENGLISH),
            ),
        ),
        claims = SdJwtVcPidClaims.all(),
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        scope = PidSdJwtVcScope,
        proofTypesSupported = ProofTypesSupported(
            ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement),
        ),
    )

typealias TimeDependant<F> = (Instant) -> F

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
    private val calculateExpiresAt: TimeDependant<Instant>,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredentials: StoreIssuedCredentials,
    private val generateStatusListToken: GenerateStatusListToken?,
    jwtProofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    override val keyAttestationRequirement: KeyAttestationRequirement,
) : IssueSpecificCredential {

    override val supportedCredential: SdJwtVcCredentialConfiguration =
        pidSdJwtVcV1(issuerSigningKey.signingAlgorithm, jwtProofsSupportedSigningAlgorithms, keyAttestationRequirement)

    override val publicKey: JWK
        get() = issuerSigningKey.key.toPublicJWK()

    private val encodePidInSdJwt = EncodePidInSdJwtVc(
        credentialIssuerId,
        hashAlgorithm,
        issuerSigningKey,
        supportedCredential.type,
    )

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Handling issuance request ...")

        val holderPubKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.now()).bind()
        val (pid, pidMetaData) = getPidData(authorizationContext).bind()
        val issuedAt = clock.now()
        val expiresAt = calculateExpiresAt(issuedAt)
        val notBefore = calculateNotUseBefore?.invoke(issuedAt)

        ensure(expiresAt > issuedAt) {
            Unexpected("exp should be after iat")
        }
        notBefore?.let {
            ensure(it > issuedAt) {
                Unexpected("nbf should be after iat")
            }
        }
        if (null != pidMetaData.issuanceDate && null != notBefore) {
            val issuanceDateAtStartOfDay = with(clock) { pidMetaData.issuanceDate.atStartOfDay() }
            ensure(issuanceDateAtStartOfDay <= notBefore) {
                Unexpected("date_of_issuance must not be after nbf")
            }
        }

        val issuedCredentials = holderPubKeys.parMap(Dispatchers.Default, 4) { holderPubKey ->
            val statusListToken = generateStatusListToken?.let {
                it(supportedCredential.type.value, expiresAt)
                    .getOrElse { error ->
                        raise(Unexpected("Unable to generate Status List Token", error))
                    }
            }
            encodePidInSdJwt(
                pid,
                pidMetaData,
                holderPubKey,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                notBefore = notBefore,
                statusListToken,
            ).bind()
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) {
            Unexpected("Unable to issue PID")
        }

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null

        storeIssuedCredentials(
            IssuedCredentials(
                format = SD_JWT_VC_FORMAT,
                type = supportedCredential.type.value,
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
