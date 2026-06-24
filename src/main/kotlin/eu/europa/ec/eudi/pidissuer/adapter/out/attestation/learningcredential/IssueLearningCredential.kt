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
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration

private val log = LoggerFactory.getLogger(IssueLearningCredential::class.java)

internal class IssueLearningCredential(
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
        val expiresAt =
            run {
                val dateOfExpiry = issuedAt + configuration.validity
                if (null != attributes.dateOfExpiry && attributes.dateOfExpiry < dateOfExpiry)
                    attributes.dateOfExpiry
                else
                    dateOfExpiry
            }

        val notificationId = generateNotificationId?.invoke()
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList

        val issuedCredentials =
            keyAttestation.credentialKeys.value
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
                encodeAttestationAttributes =
                    encodeLearningCredentialInSdJwtVc(
                        sdJwtVcSerialization = sdJwtVcSerialization,
                        digestsHashAlgorithm,
                        issuerSigningKey,
                        vct = credentialConfiguration.type,
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
                            DisplayName(
                                "Learning Credential (SD-JWT VC Compact)",
                                Locale.ENGLISH,
                            ),
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
    }
}
