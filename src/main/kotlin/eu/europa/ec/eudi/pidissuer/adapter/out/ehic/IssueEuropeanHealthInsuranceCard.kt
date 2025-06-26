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
package eu.europa.ec.eudi.pidissuer.adapter.out.ehic

import arrow.core.Either
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.IsAttribute
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.ClaimPath
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialDisplay
import eu.europa.ec.eudi.pidissuer.domain.CredentialIdentifier
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse
import eu.europa.ec.eudi.pidissuer.domain.CryptographicBindingMethod
import eu.europa.ec.eudi.pidissuer.domain.DisplayName
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredentials
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestation
import eu.europa.ec.eudi.pidissuer.domain.ProofType
import eu.europa.ec.eudi.pidissuer.domain.ProofTypesSupported
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcTypeMetadata
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Duration
import java.time.ZonedDateTime
import java.util.Locale

private val EuropeanHealthInsuranceCardScope: Scope = Scope("urn:eudi:ehic:1:dc+sd-jwt")

internal object IssuingAuthorityClaim : IsAttribute {
    val Id: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("issuing_authority").claim("id"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Issuing authority id",
        ),
    )

    val Name: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("issuing_authority").claim("name"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Issuing authority name",
        ),
    )

    override val attribute: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("issuing_authority"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Issuing authority",
        ),
        nested = listOf(Id, Name),
    )
}

internal object AuthenticSourceClaim : IsAttribute {
    val Id: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("authentic_source").claim("id"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Competent institution id",
        ),
    )

    val Name: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("authentic_source").claim("name"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Competent institution name",
        ),
    )

    override val attribute: ClaimDefinition = ClaimDefinition(
        path = ClaimPath.claim("authentic_source"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Competent institution",
        ),
        nested = listOf(Id, Name),
    )
}

internal object EuropeanHealthInsuranceCardClaims {
    val PersonalAdministrativeNumber = ClaimDefinition(
        path = ClaimPath.claim("personal_administrative_number"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Social Security PIN",
        ),
    )
    val IssuingAuthority = IssuingAuthorityClaim
    val IssuingCountry = ClaimDefinition(
        path = ClaimPath.claim("country"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Issuing country",
        ),
    )
    val DateOfExpiry = ClaimDefinition(
        path = ClaimPath.claim("date_of_expiry"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Expiry date",
        ),
    )
    val DateOfIssuance = ClaimDefinition(
        path = ClaimPath.claim("date_of_issuance"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Issue date",
        ),
    )
    val AuthenticSource = AuthenticSourceClaim
    val EndingDate = ClaimDefinition(
        path = ClaimPath.claim("ending_date"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Ending date",
        ),
    )
    val StartingDate = ClaimDefinition(
        path = ClaimPath.claim("starting_date"),
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "Starting date",
        ),
    )
    val DocumentNumber = ClaimDefinition(
        path = ClaimPath.claim("document_number"),
        mandatory = true,
        display = mapOf(
            Locale.ENGLISH to "Document number",
        ),
    )

    fun all(): List<ClaimDefinition> = listOf(
        PersonalAdministrativeNumber,
        IssuingAuthority.attribute,
        IssuingCountry,
        DateOfExpiry,
        DateOfIssuance,
        AuthenticSource.attribute,
        EndingDate,
        StartingDate,
        DocumentNumber,
    )
}

private val EuropeanHealthInsuranceCardVct: SdJwtVcType = SdJwtVcType("urn:eudi:ehic:1")

private fun europeanHealthInsuranceCardCredentialConfiguration(signingAlgorithm: JWSAlgorithm): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(EuropeanHealthInsuranceCardScope.value),
        type = EuropeanHealthInsuranceCardVct,
        scope = EuropeanHealthInsuranceCardScope,
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        display = listOf(
            CredentialDisplay(
                name = DisplayName("European Health Insurance Card", Locale.ENGLISH),
            ),
        ),
        claims = EuropeanHealthInsuranceCardClaims.all(),
        proofTypesSupported = ProofTypesSupported(
            values = nonEmptySetOf(
                ProofType.Jwt(
                    signingAlgorithmsSupported = nonEmptySetOf(
                        JWSAlgorithm.ES256,
                        JWSAlgorithm.ES384,
                        JWSAlgorithm.ES512,
                        JWSAlgorithm.RS256,
                        JWSAlgorithm.RS384,
                        JWSAlgorithm.RS512,
                    ),
                    keyAttestation = KeyAttestation.NotRequired,
                ),
            ),
        ),

    )

private val log = LoggerFactory.getLogger(IssueEuropeanHealthInsuranceCard::class.java)

internal class IssueEuropeanHealthInsuranceCard(
    issuerSigningKey: IssuerSigningKey,
    digestsHashAlgorithm: HashAlgorithm,
    integrityHashAlgorithm: IntegrityHashAlgorithm,
    private val clock: Clock,
    private val validity: Duration,
    credentialIssuerId: CredentialIssuerId,
    typeMetadata: SdJwtVcTypeMetadata,
    private val validateProofs: ValidateProofs,
    private val getEuropeanHealthInsuranceCardData: GetEuropeanHealthInsuranceCardData,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredentials: StoreIssuedCredentials,

) : IssueSpecificCredential {
    init {
        require(EuropeanHealthInsuranceCardVct.value == typeMetadata.vct.value)
        require(!validity.isNegative && !validity.isZero)
    }

    override val supportedCredential: SdJwtVcCredentialConfiguration =
        europeanHealthInsuranceCardCredentialConfiguration(issuerSigningKey.signingAlgorithm)
    override val publicKey: JWK =
        issuerSigningKey.key.toPublicJWK()

    private val encode: EncodeEuropeanHealthInsuranceCardInSdJwtVc by lazy {
        EncodeEuropeanHealthInsuranceCardInSdJwtVc(
            digestsHashAlgorithm,
            issuerSigningKey,
            integrityHashAlgorithm,
            EuropeanHealthInsuranceCardVct,
            credentialIssuerId,
            typeMetadata,
        )
    }

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Issuing EHIC")

        val holderPublicKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.instant()).bind()
        val ehic = getEuropeanHealthInsuranceCardData()
        val dateOfIssuance = ZonedDateTime.now(clock)
        val dateOfExpiry = dateOfIssuance + validity
        val issuedCredentials = holderPublicKeys.map {
            encode(ehic, authorizationContext.username, it, dateOfIssuance = dateOfIssuance, dateOfExpiry = dateOfExpiry).bind()
        }
        val notificationId = if (notificationsEnabled) generateNotificationId() else null
        storeIssuedCredentials(
            IssuedCredentials(
                SD_JWT_VC_FORMAT,
                EuropeanHealthInsuranceCardVct.value,
                authorizationContext.username,
                holderPublicKeys,
                clock.instant(),
                notificationId,
            ),
        )

        CredentialResponse.Issued(issuedCredentials, notificationId)
            .also {
                log.info("Successfully issued EHIC")
                log.debug("Issued EHIC data {}", it)
            }
    }
}
