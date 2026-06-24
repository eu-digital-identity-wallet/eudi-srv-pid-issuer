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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation

import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.EncodeAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.toECKeyOrFail
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.attestation.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.attestation.allocateStatusWithPolicy
import eu.europa.ec.eudi.pidissuer.port.out.attestation.keyAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import id.walt.mdoc.doc.MDocBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Instant

class IssueMdoc<Data>(
    override val configuration: MsoMdocCredentialConfiguration,
    private val clock: Clock,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val getAttestationAttributes: GetAttestationAttributes<Data>,
    private val allocateStatus: AllocateStatus?,
    private val encodeAttributes: EncodeAttributesInMdoc<Data>,
) : AttestationIssuer {
    private val log = LoggerFactory.getLogger(configuration.docType)

    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Handling issuance request ...")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val deviceKeys =
            keyAttestation.credentialKeys.value
                .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }
        val attributes = getAttestationAttributes()
        val expiresAt = issuedAt + configuration.validity
        val notificationId = notificationId()
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList

        val issuedCredentials =
            deviceKeys
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val statusListToken = statusListToken(expiresAt)
                    val encodedCredential =
                        encodeAttributes(
                            attributes,
                            deviceKey,
                            issuedAt = issuedAt,
                            expiresAt = expiresAt,
                            statusListToken,
                        ).also {
                            log.info("Issued $it")
                        }

                    storeIssuedCredential(
                        IssuedCredential(
                            format = MSO_MDOC_FORMAT,
                            type = configuration.docType,
                            issuedAt = issuedAt,
                            expiresAt = expiresAt,
                            notificationId = notificationId,
                            status = statusListToken,
                            clientStatus = clientStatus,
                            keyStorageStatus = keyStorageStatus,
                        ),
                    )

                    encodedCredential
                }.toNonEmptyListOrNull()

        checkNotNull(issuedCredentials) { "Cannot happen" }

        return CredentialResponse
            .Issued(issuedCredentials.map { JsonPrimitive(it) }, notificationId)
    }

    private suspend fun statusListToken(expiresAt: Instant): StatusListToken? =
        allocateStatus?.let {
            context(it) {
                allocateStatusWithPolicy(expiresAt)
            }
        }

    private suspend fun notificationId(): NotificationId? = generateNotificationId?.let { it() }

    companion object {
        operator fun <Data> invoke(
            configuration: MsoMdocCredentialConfiguration,
            clock: Clock,
            validateProof: ValidateProof,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredential: StoreIssuedCredential,
            getAttestationAttributes: GetAttestationAttributes<Data>,
            allocateStatus: AllocateStatus?,
            issuerSigningKey: IssuerSigningKey,
            usage: MDocBuilder.(Data) -> Unit,
        ): IssueMdoc<Data> =
            IssueMdoc(
                configuration,
                clock,
                validateProof,
                generateNotificationId,
                storeIssuedCredential,
                getAttestationAttributes,
                allocateStatus,
                EncodeAttributesInMdoc(configuration.docType, issuerSigningKey, usage = usage),
            )
    }
}
