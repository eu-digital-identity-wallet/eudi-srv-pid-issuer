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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.learningcredential

import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid.PidAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.SdJwtVcSerialization
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.encodeAttestationAttributesInSdJwtVc
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.attestation.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.attestation.keyAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.RFC7519
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.toJavaInstant

private val log = LoggerFactory.getLogger(IssueLearningCredential::class.java)

class IssueLearningCredential(
    override val configuration: SdJwtVcCredentialConfiguration,
    private val clock: Clock,
    private val getAttestationAttributes: GetAttestationAttributes<LearningCredential>,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val encodeAttestationAttributes: EncodeAttestationAttributes<LearningCredential>,
) : AttestationIssuer {
    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Issuing Learning Credential")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val attributes = getAttestationAttributes()
        val expiresAt = issuedAt + configuration.validity
        val notificationId = generateNotificationId?.invoke()
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList
        val issuedCredentials =
            keyAttestation.keys.value
                .parMap(Dispatchers.Default, 4) { deviceKey ->

                    val id = IssuedCredentialId.random()
                    val attestedAttributes =
                        AttestationAttributes(
                            attributes,
                            issuedAt,
                            expiresAt,
                            notBefore = issuedAt,
                            deviceKey,
                            status = null,
                            jwtId = id.value.toHexDashString(),
                        )
                    val attestationInstance = encodeAttestationAttributes(attestedAttributes)

                    storeIssuedCredential(
                        IssuedCredential(
                            format = SD_JWT_VC_FORMAT,
                            type = configuration.type.value,
                            attestedAttributes.issuedAt,
                            attestedAttributes.expiresAt,
                            notificationId,
                            attestedAttributes.status,
                            clientStatus,
                            keyStorageStatus,
                            identifier = id,
                        ),
                    )

                    attestationInstance
                }.toNonEmptyListOrNull()

        // This is runtime error, not a business error
        checkNotNull(issuedCredentials) { "Cannot happen" }

        return CredentialResponse
            .Issued(issuedCredentials, notificationId)
            .also {
                log.info("Successfully issued Learning Credential")
                log.debug("Issued Learning Credential data {}", it)
            }
    }

    companion object {
        operator fun invoke(
            sdJwtVcSerialization: SdJwtVcSerialization = SdJwtVcSerialization.Compact,
            clock: Clock,
            getAttestationAttributes: GetAttestationAttributes<LearningCredential>,
            issuerSigningKey: IssuerSigningKey,
            digestsHashAlgorithm: HashAlgorithm,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validity: Duration,
            validateProof: ValidateProof,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredential: StoreIssuedCredential,
        ): IssueLearningCredential {
            val credentialConfiguration = cfg(deviceBinding, credentialReusePolicy, validity, issuerSigningKey)
            return IssueLearningCredential(
                credentialConfiguration,
                clock,
                getAttestationAttributes,
                validateProof,
                generateNotificationId,
                storeIssuedCredential,
                encodeAttestationAttributesInSdJwtVc(
                    sdJwtVcSerialization,
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    vct = credentialConfiguration.type,
                    build = { learningCredential(it) },
                ),
            )
        }

        fun randomLearningCredentials(
            clock: Clock,
            getPidData: GetAttestationAttributes<PidAttributes>,
        ): GetAttestationAttributes<LearningCredential> =
            GetAttestationAttributes {
                val (pid, _) = getPidData()
                context(clock, Random) { LearningCredential.random(pid) }
            }
    }
}

private fun cfg(
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy,
    validity: Duration,
    issuerSigningKey: IssuerSigningKey,
): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        CredentialConfigurationId("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"),
        Scope("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt"),
        display =
            nonEmptyListOf(
                CredentialDisplay(
                    DisplayName.en("Learning Credential (SD-JWT VC Compact)"),
                ),
            ),
        claims = SdJwtVcClaims.all(),
        deviceBinding = deviceBinding,
        category = AttestationCategory.Eaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
        type = SdJwtVcType("urn:eu.europa.ec.eudi:learning:credential:1"),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(issuerSigningKey.signingAlgorithm),
        publicKey = issuerSigningKey.key.toPublicJWK(),
    )

fun SdJwtObjectBuilder.learningCredential(learningCredential: LearningCredential) {
    val formatter: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE
    with(learningCredential) {
        with(issuer) {
            claim(SdJwtVcClaims.IssuingAuthority.name, name.value)
            claim(SdJwtVcClaims.IssuingCountry.name, country.code)
            claim(RFC7519.ISSUER, uri.externalForm)
        }
        claim(
            SdJwtVcClaims.DateOfIssuance.name,
            formatter.format(ZonedDateTime.ofInstant(dateOfIssuance.toJavaInstant(), ZoneOffset.UTC)),
        )
        if (null != dateOfExpiry) {
            claim(
                SdJwtVcClaims.DateOfExpiry.name,
                formatter.format(ZonedDateTime.ofInstant(dateOfExpiry.toJavaInstant(), ZoneOffset.UTC)),
            )
        }
        sdClaim(SdJwtVcClaims.FamilyName.name, familyName.value)
        if (null != givenName) {
            sdClaim(SdJwtVcClaims.GivenName.name, givenName.value)
        }
        claim(SdJwtVcClaims.AchievementTitle.name, achievementTitle.value)
        if (null != achievementDescription) {
            claim(SdJwtVcClaims.AchievementDescription.name, achievementDescription.value)
        }
        if (null != learningOutcomes) {
            sdArrClaim(SdJwtVcClaims.LearningOutcomes.name) {
                learningOutcomes.forEach { learningOutcome -> claim(learningOutcome.value) }
            }
        }
        if (null != assessmentGrade) {
            sdClaim(SdJwtVcClaims.AssessmentGrade.name, assessmentGrade.value)
        }
        arrClaim(SdJwtVcClaims.LanguageOfClasses.name) {
            languagesOfClasses.forEach { languageOfClasses -> claim(languageOfClasses.value) }
        }
        sdClaim(SdJwtVcClaims.LearnerIdentification.name, learnerIdentification.value)
        sdClaim(SdJwtVcClaims.ExpectedStudyTime.name, expectedStudyTime.value)
        sdClaim(SdJwtVcClaims.LevelOfLearningExperience.name, levelOfLearningExperience.value)
        sdArrClaim(SdJwtVcClaims.TypesOfQualityAssurance.name) {
            typesOfQualityAssurance.forEach { typeOfQualityAssurance -> claim(typeOfQualityAssurance.value) }
        }
        if (null != prerequisitesToEnroll) {
            sdArrClaim(SdJwtVcClaims.PrerequisitesToEnroll.name) {
                prerequisitesToEnroll.forEach { prerequisiteToEnroll -> claim(prerequisiteToEnroll.value) }
            }
        }
        if (null != integrationStackabilityOptions) {
            sdClaim(SdJwtVcClaims.IntegrationStackabilityOptions.name, integrationStackabilityOptions.value)
        }
    }
}

private val Language.value: String
    get() =
        when (this) {
            Language.EN -> "en"
            Language.JP -> "jp"
        }

private val LevelOfLearningExperience.value: Int
    get() =
        when (this) {
            LevelOfLearningExperience.Level1 -> 1
            LevelOfLearningExperience.Level2 -> 2
            LevelOfLearningExperience.Level3 -> 3
            LevelOfLearningExperience.Level4 -> 4
            LevelOfLearningExperience.Level5 -> 5
            LevelOfLearningExperience.Level6 -> 6
            LevelOfLearningExperience.Level7 -> 7
            LevelOfLearningExperience.Level8 -> 8
        }

private val IntegrationStackabilityOptions.value: Boolean
    get() =
        when (this) {
            IntegrationStackabilityOptions.Yes -> true
            IntegrationStackabilityOptions.No -> false
        }
