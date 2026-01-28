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

import arrow.core.Either
import arrow.core.NonEmptySet
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import java.util.*
import kotlin.time.Duration

private val log = LoggerFactory.getLogger(IssueLearningCredential::class.java)

internal class IssueLearningCredential(
    override val supportedCredential: CredentialConfiguration,
    override val publicKey: JWK,
    override val keyAttestationRequirement: KeyAttestationRequirement,
    private val clock: Clock,
    private val validateProofs: ValidateProofs,
    private val getLearningCredential: GetLearningCredential,
    private val validity: Duration,
    private val encodeLearningCredential: EncodeLearningCredential,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredentials: StoreIssuedCredentials,
) : IssueSpecificCredential {
    init {
        require(!publicKey.isPrivate)
        require(validity.isPositive())
    }

    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Issuing Learning Credential")

        val holderKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.now()).bind()
        val learningCredential = getLearningCredential(authorizationContext)
        val issuedAt = clock.now()
        val expiresAt = run {
            val dateOfExpiry = issuedAt + validity
            if (null != learningCredential.dateOfExpiry && learningCredential.dateOfExpiry < dateOfExpiry) learningCredential.dateOfExpiry
            else dateOfExpiry
        }

        val issuedCredentials = holderKeys.parMap(Dispatchers.Default, 4) {
            encodeLearningCredential(learningCredential, it, issuedAt = issuedAt, expiresAt = expiresAt).bind()
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) {
            IssueCredentialError.Unexpected("Unable to issue Learning Credential")
        }

        val notificationId = generateNotificationId?.invoke()
        storeIssuedCredentials(
            IssuedCredentials(
                encodeLearningCredential.format,
                encodeLearningCredential.type,
                authorizationContext.username,
                holderKeys,
                issuedAt,
                notificationId,
            ),
        )

        CredentialResponse.Issued(issuedCredentials, notificationId)
            .also {
                log.info("Successfully issued Learning Credential")
                log.debug("Issued Learning Credential data {}", it)
            }
    }

    companion object {
        fun sdJwtVcCompact(
            issuerSigningKey: IssuerSigningKey,
            proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
            keyAttestationRequirement: KeyAttestationRequirement,
            clock: Clock,
            validateProofs: ValidateProofs,
            getPidData: GetPidData,
            validity: Duration,
            digestsHashAlgorithm: HashAlgorithm,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredentials: StoreIssuedCredentials,
        ): IssueLearningCredential {
            val credentialConfiguration = LearningCredential.sdJwtVcCredentialConfiguration(
                CredentialConfigurationId("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"),
                Scope("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt"),
                issuerSigningKey.signingAlgorithm,
                CredentialDisplay(DisplayName("Learning Credential (SD-JWT VC Compact)", Locale.ENGLISH)),
                proofsSupportedSigningAlgorithms,
                keyAttestationRequirement,
            )
            return IssueLearningCredential(
                credentialConfiguration,
                issuerSigningKey.key.toPublicJWK(),
                keyAttestationRequirement,
                clock,
                validateProofs,
                GetLearningCredential.mock(clock, getPidData),
                validity,
                EncodeLearningCredential.sdJwtVcCompact(
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    credentialConfiguration.type,
                ),
                generateNotificationId,
                storeIssuedCredentials,
            )
        }
    }
}
