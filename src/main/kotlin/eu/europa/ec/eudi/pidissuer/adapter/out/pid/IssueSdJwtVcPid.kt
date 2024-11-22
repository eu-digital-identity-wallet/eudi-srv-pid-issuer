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

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
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
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.util.*
import eu.europa.ec.eudi.pidissuer.adapter.out.oauth.OidcGender as OidcGenderAttribute

val PidSdJwtVcScope: Scope = Scope("${PID_DOCTYPE}_vc_sd_jwt")

internal object Attributes {

    val AgeBirthYear = AttributeDetails(
        name = "age_birth_year",
        mandatory = false,
    )
    val AgeEqualOrOver = AttributeDetails(
        name = "age_equal_or_over",
        display = mapOf(Locale.ENGLISH to "Age attestations"),
    )
    val AgeOver18 = AttributeDetails(
        name = "18",
        display = mapOf(Locale.ENGLISH to "Adult or minor"),
    )

    val AgeInYears = AttributeDetails(
        name = "age_in_years",
        display = mapOf(Locale.ENGLISH to "The subject’s current age in years."),
    )

    val pidAttributes: List<AttributeDetails> = listOf(
        OidcFamilyName,
        OidcGivenName,
        OidcBirthDate,
        AgeEqualOrOver,
        AgeInYears,
        AgeBirthYear,
        OidcAssuranceBirthFamilyName,
        OidcAssuranceBirthGivenName,
        OidcAssurancePlaceOfBirth.attribute,
        OidcAddressClaim.attribute,
        OidcGenderAttribute,
        OidcAssuranceNationalities,
        IssuingAuthorityAttribute,
        DocumentNumberAttribute,
        AdministrativeNumberAttribute,
        IssuingCountryAttribute,
        IssuingJurisdictionAttribute,
    )
}

fun pidSdJwtVcV1(signingAlgorithm: JWSAlgorithm): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSdJwtVcScope.value),
        type = SdJwtVcType(pidDocType(1)),
        display = pidDisplay,
        claims = Attributes.pidAttributes,
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(signingAlgorithm),
        scope = PidSdJwtVcScope,
        proofTypesSupported = ProofTypesSupported(nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256)))),
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
    )

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): CredentialResponse = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.instant())

        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null
        val issuedCredentials = holderPubKeys.map { holderPubKey ->
            val sdJwt = encodePidInSdJwt.invoke(pid, pidMetaData, holderPubKey)
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
