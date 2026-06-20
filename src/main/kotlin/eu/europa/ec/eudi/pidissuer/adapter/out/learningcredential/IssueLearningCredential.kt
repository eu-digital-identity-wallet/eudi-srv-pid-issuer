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
package eu.europa.ec.eudi.pidissuer.adapter.out.learningcredential

import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.context.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.credential.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant

private val log = LoggerFactory.getLogger(IssueLearningCredential::class.java)

internal class IssueLearningCredential(
    override val supportedCredential: SdJwtVcCredentialConfiguration,
    override val publicKey: JWK,
    override val keyAttestationRequirement: KeyAttestationRequirement,
    private val clock: Clock,
    private val getLearningCredential: GetLearningCredential,
    override val validity: Duration,
    private val encodeLearningCredential: EncodeLearningCredential,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val validateProof: ValidateProof,
) : AttestationIssuer {
    init {
        require(!publicKey.isPrivate)
        require(validity.isPositive())
    }

    context(_: Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): CredentialResponse {
        log.info("Issuing Learning Credential")

        val issuedAt = clock.now()
        val keyAttestation = keyAttestation(request, issuedAt)
        val learningCredentialAttributes = getLearningCredential(authorizationContext)

        val expiresAt =
            run {
                val dateOfExpiry = issuedAt + validity
                if (null != learningCredentialAttributes.dateOfExpiry && learningCredentialAttributes.dateOfExpiry < dateOfExpiry)
                    learningCredentialAttributes.dateOfExpiry
                else
                    dateOfExpiry
            }

        val notificationId = if (notificationsEnabled) generateNotificationId() else null
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList

        val issuedCredentials =
            keyAttestation.credentialKeys.value
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val encodedCredential =
                        encodeLearningCredential(
                            learningCredentialAttributes,
                            deviceKey,
                            issuedAt,
                            expiresAt,
                        )

                    storeIssuedCredential(
                        IssuedCredential(
                            encodeLearningCredential.format,
                            encodeLearningCredential.type,
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

        // This is runtime error, not a business error
        checkNotNull(issuedCredentials) { "Cannot happen" }

        return CredentialResponse
            .Issued(issuedCredentials, notificationId)
            .also {
                log.info("Successfully issued Learning Credential")
                log.debug("Issued Learning Credential data {}", it)
            }
    }

    context(_: Raise<IssueCredentialError>)
    private suspend fun keyAttestation(
        request: CredentialRequest,
        at: Instant,
    ): KeyAttestation {
        check(supportedCredential.proofTypesSupported.values.isNotEmpty()) {
            "No proof types supported set"
        }
        val proof =
            context(validateProof, supportedCredential) {
                validateProof(request.unvalidatedProof, at)
            }
        ensureNotNull(proof) {
            IssueCredentialError.MissingProof
        }
        return proof
    }

    companion object {
        fun sdJwtVcCompact(
            issuerSigningKey: IssuerSigningKey,
            proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
            keyAttestationRequirement: KeyAttestationRequirement,
            clock: Clock,
            getPidData: GetPidData,
            validity: Duration,
            digestsHashAlgorithm: HashAlgorithm,
            notificationsEnabled: Boolean,
            generateNotificationId: GenerateNotificationId,
            storeIssuedCredential: StoreIssuedCredential,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validateProof: ValidateProof,
        ): IssueLearningCredential {
            val credentialConfiguration =
                LearningCredential.sdJwtVcCredentialConfiguration(
                    CredentialConfigurationId("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"),
                    Scope("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt"),
                    issuerSigningKey.signingAlgorithm,
                    CredentialDisplay(DisplayName("Learning Credential (SD-JWT VC Compact)", Locale.ENGLISH)),
                    proofsSupportedSigningAlgorithms,
                    keyAttestationRequirement,
                    credentialReusePolicy,
                )
            return IssueLearningCredential(
                credentialConfiguration,
                issuerSigningKey.key.toPublicJWK(),
                keyAttestationRequirement,
                clock,
                GetLearningCredential.mock(clock, getPidData),
                validity,
                EncodeLearningCredential.sdJwtVcCompact(
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    credentialConfiguration.type,
                ),
                notificationsEnabled,
                generateNotificationId,
                storeIssuedCredential,
                validateProof,
            )
        }
    }
}
