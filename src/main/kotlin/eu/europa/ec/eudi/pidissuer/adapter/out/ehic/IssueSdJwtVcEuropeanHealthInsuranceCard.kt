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
package eu.europa.ec.eudi.pidissuer.adapter.out.ehic

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.IsAttribute
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.attestation.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.attestation.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.attestation.keyAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration

private val EuropeanHealthInsuranceCardScope: Scope = Scope("urn:eudi:ehic:1:dc+sd-jwt")

internal object IssuingAuthorityClaim : IsAttribute {
    val Id: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority").claim("id"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Issuing authority id",
                ),
        )

    val Name: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority").claim("name"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Issuing authority name",
                ),
        )

    override val attribute: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Issuing authority",
                ),
            nested = listOf(Id, Name),
        )
}

internal object AuthenticSourceClaim : IsAttribute {
    val Id: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("authentic_source").claim("id"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Competent institution id",
                ),
        )

    val Name: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("authentic_source").claim("name"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Competent institution name",
                ),
        )

    override val attribute: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("authentic_source"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Competent institution",
                ),
            nested = listOf(Id, Name),
        )
}

internal object EuropeanHealthInsuranceCardClaims {
    val PersonalAdministrativeNumber =
        ClaimDefinition(
            path = ClaimPath.claim("personal_administrative_number"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Social Security PIN",
                ),
        )
    val IssuingCountry =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_country"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Issuing country",
                ),
        )
    val IssuingAuthority = IssuingAuthorityClaim
    val DateOfExpiry =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_expiry"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Expiry date",
                ),
        )
    val DateOfIssuance =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_issuance"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Issue date",
                ),
        )
    val AuthenticSource = AuthenticSourceClaim
    val EndingDate =
        ClaimDefinition(
            path = ClaimPath.claim("ending_date"),
            mandatory = false,
            display =
                mapOf(
                    Locale.ENGLISH to "Ending date",
                ),
        )
    val StartingDate =
        ClaimDefinition(
            path = ClaimPath.claim("starting_date"),
            mandatory = false,
            display =
                mapOf(
                    Locale.ENGLISH to "Starting date",
                ),
        )
    val DocumentNumber =
        ClaimDefinition(
            path = ClaimPath.claim("document_number"),
            mandatory = true,
            display =
                mapOf(
                    Locale.ENGLISH to "Document number",
                ),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
            PersonalAdministrativeNumber,
            IssuingCountry,
            IssuingAuthority.attribute,
            DateOfExpiry,
            DateOfIssuance,
            AuthenticSource.attribute,
            EndingDate,
            StartingDate,
            DocumentNumber,
        )
}

private val EuropeanHealthInsuranceCardVct: SdJwtVcType = SdJwtVcType("urn:eudi:ehic:1")

private fun europeanHealthInsuranceCardCredentialConfiguration(
    signingAlgorithm: JWSAlgorithm,
    publicKey: JWK,
    credentialConfigurationId: CredentialConfigurationId,
    scope: Scope,
    credentialDisplay: CredentialDisplay,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        credentialConfigurationId,
        scope,
        listOf(credentialDisplay),
        deviceBinding,
        AttestationCategory.EuPubEaa,
        credentialReusePolicy,
        validity,
        EuropeanHealthInsuranceCardVct,
        nonEmptySetOf(signingAlgorithm),
        publicKey,
        EuropeanHealthInsuranceCardClaims.all(),
    )

private val log = LoggerFactory.getLogger(IssueSdJwtVcEuropeanHealthInsuranceCard::class.java)

internal class IssueSdJwtVcEuropeanHealthInsuranceCard private constructor(
    override val configuration: SdJwtVcCredentialConfiguration,
    private val encode: EncodeEuropeanHealthInsuranceCardInSdJwtVc,
    private val clock: Clock,
    private val getAttestationAttributes: GetAttestationAttributes<EuropeanHealthInsuranceCard>,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val validateProof: ValidateProof,
) : AttestationIssuer {
    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Issuing DC4EU EHIC")

        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val ehicAttributes = getAttestationAttributes()
        val expiresAt = issuedAt + configuration.validity
        val notificationId = if (notificationsEnabled) generateNotificationId() else null
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList

        val issuedCredentials =
            keyAttestation.credentialKeys.value
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val encodedCredential =
                        encode(
                            ehicAttributes,
                            holder = authorizationContext.username,
                            deviceKey,
                            issuedAt,
                            expiresAt,
                        )

                    storeIssuedCredential(
                        IssuedCredential(
                            SD_JWT_VC_FORMAT,
                            type = EuropeanHealthInsuranceCardVct.value,
                            issuedAt,
                            expiresAt,
                            notificationId,
                            status = null,
                            clientStatus,
                            keyStorageStatus,
                        ),
                    )

                    encodedCredential
                }.toNonEmptyListOrNull()

        // That's a runtime error, not a business error
        checkNotNull(issuedCredentials) { "Cannot happen" }

        return CredentialResponse
            .Issued(issuedCredentials, notificationId)
            .also {
                log.info("Successfully issued DC4EU EHIC")
                log.debug("Issued DC4EU EHIC data {}", it)
            }
    }

    companion object {
        fun jwsJsonFlattened(
            issuerSigningKey: IssuerSigningKey,
            digestsHashAlgorithm: HashAlgorithm,
            credentialIssuerId: CredentialIssuerId,
            clock: Clock,
            validity: Duration,
            getAttestationAttributes: GetAttestationAttributes<EuropeanHealthInsuranceCard>,
            notificationsEnabled: Boolean,
            generateNotificationId: GenerateNotificationId,
            storeIssuedCredential: StoreIssuedCredential,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validateProof: ValidateProof,
        ): IssueSdJwtVcEuropeanHealthInsuranceCard =
            IssueSdJwtVcEuropeanHealthInsuranceCard(
                europeanHealthInsuranceCardCredentialConfiguration(
                    issuerSigningKey.signingAlgorithm,
                    issuerSigningKey.key.toPublicJWK(),
                    CredentialConfigurationId("urn:eudi:ehic:1:dc+sd-jwt-jws-json"),
                    EuropeanHealthInsuranceCardScope,
                    CredentialDisplay(
                        name = DisplayName("DC4EU European Health Insurance Card (SD-JWT VC JWS JSON)", Locale.ENGLISH),
                    ),
                    deviceBinding,
                    credentialReusePolicy,
                    validity,
                ),
                EncodeEuropeanHealthInsuranceCardInSdJwtVc.jwsJsonFlattened(
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    EuropeanHealthInsuranceCardVct,
                    credentialIssuerId,
                ),
                clock,
                getAttestationAttributes,
                notificationsEnabled,
                generateNotificationId,
                storeIssuedCredential,
                validateProof,
            )

        fun compact(
            issuerSigningKey: IssuerSigningKey,
            digestsHashAlgorithm: HashAlgorithm,
            credentialIssuerId: CredentialIssuerId,
            clock: Clock,
            validity: Duration,
            getAttestationAttributes: GetAttestationAttributes<EuropeanHealthInsuranceCard>,
            notificationsEnabled: Boolean,
            generateNotificationId: GenerateNotificationId,
            storeIssuedCredential: StoreIssuedCredential,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validateProof: ValidateProof,
        ): IssueSdJwtVcEuropeanHealthInsuranceCard =
            IssueSdJwtVcEuropeanHealthInsuranceCard(
                europeanHealthInsuranceCardCredentialConfiguration(
                    issuerSigningKey.signingAlgorithm,
                    issuerSigningKey.key.toPublicJWK(),
                    CredentialConfigurationId("urn:eudi:ehic:1:dc+sd-jwt-compact"),
                    EuropeanHealthInsuranceCardScope,
                    CredentialDisplay(
                        name = DisplayName("DC4EU European Health Insurance Card (SD-JWT VC Compact)", Locale.ENGLISH),
                    ),
                    deviceBinding,
                    credentialReusePolicy,
                    validity,
                ),
                EncodeEuropeanHealthInsuranceCardInSdJwtVc.compact(
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    EuropeanHealthInsuranceCardVct,
                    credentialIssuerId,
                ),
                clock,
                getAttestationAttributes,
                notificationsEnabled,
                generateNotificationId,
                storeIssuedCredential,
                validateProof,
            )
    }
}
