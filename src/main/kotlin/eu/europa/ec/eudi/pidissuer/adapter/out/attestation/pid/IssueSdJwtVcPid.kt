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
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant

val PidSdJwtVcScope: Scope = Scope("eu.europa.ec.eudi.pid_vc_sd_jwt")

@Suppress("SameParameterValue")
private fun pidDocType(version: Int): String = "urn:eudi:pid:$version"

typealias TimeDependant<F> = (Instant) -> F

private val log = LoggerFactory.getLogger(IssueSdJwtVcPid::class.java)

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid private constructor(
    override val configuration: SdJwtVcCredentialConfiguration,
    private val clock: Clock,
    private val getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
    private val encodeAttestationAttributes: EncodeAttestationAttributes<PidAttributes>,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val allocateStatus: AllocateStatus,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
) : AttestationIssuer {
    private fun nbf(issuedAt: Instant): Instant? =
        calculateNotUseBefore
            ?.invoke(issuedAt)
            ?.also { nbf -> check(nbf > issuedAt) { "nbf should be after iat" } }

    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Handling issuance request ...")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val deviceKeys = keyAttestation.keys.value
        val attributes = getAttestationAttributes()
        val expiresAt = issuedAt + configuration.validity
        val notBefore = nbf(issuedAt)
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
                pidSdJwtVcV1Cfg(
                    issuerSigningKey.signingAlgorithm,
                    publicKey,
                    deviceBinding,
                    credentialReusePolicy,
                    validity,
                )
            return IssueSdJwtVcPid(
                configuration,
                clock,
                getAttestationAttributes,
                encodeAttestationAttributesInSdJwtVc(
                    SdJwtVcSerialization.Compact,
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    vct = configuration.type,
                    issuer = credentialIssuerId,
                    build = { pid(it) },
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

private fun pidSdJwtVcV1Cfg(
    signingAlgorithm: JWSAlgorithm,
    publicKey: JWK,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSdJwtVcScope.value),
        type = SdJwtVcType(pidDocType(1)),
        display = CredentialDisplay(DisplayName.en("PID (SD-JWT VC Compact)")).nel(),
        claims = SdJwtVcPidClaims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        publicKey = publicKey,
        scope = PidSdJwtVcScope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Pid,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

fun SdJwtObjectBuilder.pid(attributes: PidAttributes) {
    val (pid, pidMetaData) = attributes
    //
    // Selectively Disclosed claims
    //
    sdClaim(SdJwtVcPidClaims.FamilyName.name, pid.familyName.value)
    sdClaim(SdJwtVcPidClaims.GivenName.name, pid.givenName.value)
    sdClaim(SdJwtVcPidClaims.BirthDate.name, pid.birthDate.toString())
    with(pid.placeOfBirth) {
        sdObjClaim(SdJwtVcPidClaims.PlaceOfBirth.attribute.name) {
            country?.let { sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Country.name, it.value) }
            region?.let { sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Region.name, it.value) }
            locality?.let { sdClaim(SdJwtVcPidClaims.PlaceOfBirth.Locality.name, it.value) }
        }
    }
    sdArrClaim(SdJwtVcPidClaims.Nationalities.name) {
        pid.nationalities.forEach { sdClaim(it.value) }
    }
    pid.oidcAddressClaim()?.let { address ->
        sdObjClaim(SdJwtVcPidClaims.Address.attribute.name) {
            address.formatted?.let { sdClaim(SdJwtVcPidClaims.Address.Formatted.name, it) }
            address.houseNumber?.let { sdClaim(SdJwtVcPidClaims.Address.HouseNumber.name, it) }
            address.streetAddress?.let { sdClaim(SdJwtVcPidClaims.Address.Street.name, it) }
            address.locality?.let { sdClaim(SdJwtVcPidClaims.Address.Locality.name, it) }
            address.region?.let { sdClaim(SdJwtVcPidClaims.Address.Region.name, it) }
            address.postalCode?.let { sdClaim(SdJwtVcPidClaims.Address.PostalCode.name, it) }
            address.country?.let { sdClaim(SdJwtVcPidClaims.Address.Country.name, it) }
        }
    }
    pid.personalAdministrativeNumber?.let { sdClaim(SdJwtVcPidClaims.PersonalAdministrativeNumber.name, it.value) }
    pid.portrait?.let {
        val encodedBytes =
            when (it) {
                is PortraitImage.JPEG -> {
                    kotlin.io.encoding.Base64
                        .encode(it.value)
                }

                is PortraitImage.JPEG2000 -> {
                    Base64.encode(it.value)
                }
            }
        val url = "data:image/jpeg;base64,$encodedBytes"
        sdClaim(SdJwtVcPidClaims.Picture.name, url)
    }
    pid.familyNameBirth?.let { sdClaim(SdJwtVcPidClaims.BirthFamilyName.name, it.value) }
    pid.givenNameBirth?.let { sdClaim(SdJwtVcPidClaims.BirthGivenName.name, it.value) }
    pid.sex?.let { sdClaim(SdJwtVcPidClaims.Sex.name, it.value.toInt()) }
    pid.emailAddress?.let { sdClaim(SdJwtVcPidClaims.Email.name, it) }
    pid.mobilePhoneNumber?.let { sdClaim(SdJwtVcPidClaims.PhoneNumber.name, it.value) }

    sdClaim(SdJwtVcPidClaims.DateOfExpiry.name, pidMetaData.expiryDate.toString())
    sdClaim(SdJwtVcPidClaims.IssuingAuthority.name, pidMetaData.issuingAuthority.valueAsString())
    sdClaim(SdJwtVcPidClaims.IssuingCountry.name, pidMetaData.issuingCountry.value)
    pidMetaData.documentNumber?.let { sdClaim(SdJwtVcPidClaims.DocumentNumber.name, it.value) }
    pidMetaData.issuingJurisdiction?.let { sdClaim(SdJwtVcPidClaims.IssuingJurisdiction.name, it) }
    pidMetaData.issuanceDate?.let { sdClaim(SdJwtVcPidClaims.DateOfIssuance.name, it.toString()) }
    pidMetaData.attestationLegalCategory?.let { sdClaim(SdJwtVcPidClaims.AttestationLegalCategory.name, it) }
}

private fun Pid.oidcAddressClaim(): OidcAddressClaim? =
    if (
        residentHouseNumber != null || residentStreet != null || residentPostalCode != null ||
        residentCity != null || residentState != null || residentCountry != null ||
        residentAddress != null
    ) {
        OidcAddressClaim(
            formatted = residentAddress,
            country = residentCountry?.value,
            region = residentState?.value,
            locality = residentCity?.value,
            postalCode = residentPostalCode?.value,
            streetAddress = residentStreet?.value,
            houseNumber = residentHouseNumber,
        )
    } else {
        null
    }
