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

import arrow.core.*
import arrow.core.raise.Raise
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.*
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.SdJwtVcSerialization
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.encodeAttestationAttributesInSdJwtVc
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.attestation.*
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration
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
    val Sex =
        ClaimDefinition(
            path = ClaimPath.claim("sex"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Sex"),
        )
    val Nationalities = OidcAssuranceNationalities
    val IssuingAuthority =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority"),
        )
    val DocumentNumber =
        ClaimDefinition(
            path = ClaimPath.claim("document_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Document Number"),
        )
    val PersonalAdministrativeNumber =
        ClaimDefinition(
            path = ClaimPath.claim("personal_administrative_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Personal Administrative Number"),
        )
    val IssuingCountry =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_country"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Country"),
        )
    val IssuingJurisdiction =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_jurisdiction"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Issuing Jurisdiction"),
        )
    val Email =
        ClaimDefinition(
            path = ClaimPath.claim("email"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Email Address"),
        )
    val PhoneNumber =
        ClaimDefinition(
            path = ClaimPath.claim("phone_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Mobile Phone Number"),
        )
    val Picture =
        ClaimDefinition(
            path = ClaimPath.claim("picture"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Portrait Image"),
        )
    val DateOfExpiry =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_expiry"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Expiry Date"),
        )
    val DateOfIssuance =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_issuance"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Issuance Date"),
        )
    val TrustAnchor =
        ClaimDefinition(
            path = ClaimPath.claim("trust_anchor"),
            mandatory = false,
            display =
                mapOf(
                    Locale.ENGLISH to "Trust Anchor",
                ),
        )
    val AttestationLegalCategory =
        ClaimDefinition(
            path = ClaimPath.claim("attestation_legal_category"),
            mandatory = false,
            display =
                mapOf(
                    Locale.ENGLISH to "Attestation Legal Category",
                ),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
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
            AttestationLegalCategory,
        )
}

@Suppress("SameParameterValue")
private fun pidDocType(version: Int): String = "urn:eudi:pid:$version"

internal val SdJwtVcPidVct: SdJwtVcType = SdJwtVcType(pidDocType(1))

internal val SdJwtVcPidCredentialConfigurationId: CredentialConfigurationId =
    CredentialConfigurationId(PidSdJwtVcScope.value)

fun pidSdJwtVcV1(
    signingAlgorithm: JWSAlgorithm,
    publicKey: JWK,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = SdJwtVcPidCredentialConfigurationId,
        type = SdJwtVcPidVct,
        display =
            listOf(
                CredentialDisplay(
                    name = DisplayName("PID (SD-JWT VC Compact)", Locale.ENGLISH),
                ),
            ),
        claims = SdJwtVcPidClaims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        publicKey = publicKey,
        scope = PidSdJwtVcScope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Pid,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

typealias TimeDependant<F> = (Instant) -> F

private val log = LoggerFactory.getLogger(IssueSdJwtVcPid::class.java)

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid private constructor(
    override val configuration: SdJwtVcCredentialConfiguration,
    private val clock: Clock,
    private val timeZone: TimeZone,
    private val getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
    private val encodeAttestationAttributes: EncodeAttestationAttributes<PidAttributes>,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val allocateStatus: AllocateStatus,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
) : AttestationIssuer {
    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Handling issuance request ...")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val deviceKeys = keyAttestation.credentialKeys.value
        val attributes = getAttestationAttributes()
        val expiresAt = issuedAt + configuration.validity
        val notBefore =
            calculateNotUseBefore
                ?.invoke(issuedAt)
                ?.also { nbf -> check(nbf > issuedAt) { "nbf should be after iat" } }
        if (null != attributes.metaData.issuanceDate && null != notBefore) {
            val issuanceDateAtStartOfDay = attributes.metaData.issuanceDate.atStartOfDayIn(timeZone)
            check(issuanceDateAtStartOfDay <= notBefore) {
                // Runtime error, not a business error
                "date_of_issuance must not be after nbf"
            }
        }

        val notificationId = generateNotificationId?.invoke()
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList
        val issuedCredentials =
            deviceKeys
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val status =
                        context(allocateStatus) {
                            allocateStatusWithPolicy(expiresAt)
                        }
                    val attestationAttributes =
                        AttestationAttributes(
                            attributes,
                            issuedAt,
                            expiresAt,
                            notBefore = notBefore,
                            deviceKey,
                            status,
                            jwtId = null,
                        )
                    val attestation =
                        encodeAttestationAttributes(attestationAttributes)

                    storeIssuedCredential(
                        IssuedCredential(
                            format = SD_JWT_VC_FORMAT,
                            type = configuration.type.value,
                            issuedAt = attestationAttributes.issuedAt,
                            expiresAt = attestationAttributes.expiresAt,
                            notificationId = notificationId,
                            status = attestationAttributes.status,
                            clientStatus = clientStatus,
                            keyStorageStatus = keyStorageStatus,
                        ),
                    )

                    attestation
                }.toNonEmptyListOrNull()

        checkNotNull(issuedCredentials) {
            // That's a runtime error, not a business error
            "Cannot happen"
        }

        return CredentialResponse
            .Issued(issuedCredentials, notificationId)
            .also { issued ->
                log.info("Issued PID {}", issued)
            }
    }

    companion object {
        operator fun invoke(
            clock: Clock,
            timeZone: TimeZone,
            getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
            issuerSigningKey: IssuerSigningKey,
            credentialIssuerId: CredentialIssuerId,
            digestsHashAlgorithm: HashAlgorithm,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validity: Duration,
            validateProof: ValidateProof,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredential: StoreIssuedCredential,
            allocateStatus: AllocateStatus,
            calculateNotUseBefore: TimeDependant<Instant>?,
        ): IssueSdJwtVcPid {
            val publicKey = issuerSigningKey.key.toPublicJWK()
            val configuration =
                pidSdJwtVcV1(
                    issuerSigningKey.signingAlgorithm,
                    publicKey,
                    deviceBinding,
                    credentialReusePolicy,
                    validity,
                )
            return IssueSdJwtVcPid(
                configuration,
                clock,
                timeZone,
                getAttestationAttributes,
                encodeAttestationAttributesInSdJwtVc(
                    SdJwtVcSerialization.Compact,
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    vct = configuration.type,
                    issuer = credentialIssuerId,
                    build = { sdJwtSpec(it) },
                ),
                validateProof,
                generateNotificationId,
                storeIssuedCredential,
                allocateStatus,
                calculateNotUseBefore,
            )
        }
    }
}
