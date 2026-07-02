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
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.encodeAttestationAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
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
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Instant

class IssueMdoc<Attr>(
    override val configuration: MsoMdocCredentialConfiguration,
    private val clock: Clock,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val getAttestationAttributes: GetAttestationAttributes<Attr>,
    private val allocateStatus: AllocateStatus?,
    private val encodeAttestationAttributes: EncodeAttestationAttributes<Attr>,
) : AttestationIssuer {
    private val log = LoggerFactory.getLogger(configuration.docType)

    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Handling issuance request ...")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val deviceKeys = keyAttestation.keys.value
        val attributes = getAttestationAttributes()
        val notificationId = generateNotificationId?.invoke()
        val clientStatus = authorizationContext.clientStatus
        val keyStorageStatus = keyAttestation.keyStorageStatus.status.statusList
        val expiresAt = issuedAt + configuration.validity
        val issuedInstances =
            deviceKeys
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val attestedAttributes =
                        AttestationAttributes(
                            attributes,
                            issuedAt,
                            expiresAt,
                            notBefore = null,
                            deviceKey,
                            status = statusListToken(expiresAt),
                        )
                    val instance = encodeAttestationAttributes(attestedAttributes).also { log.info("Issued $it") }

                    storeIssuedCredential(
                        IssuedCredential(
                            format = MSO_MDOC_FORMAT,
                            type = configuration.docType,
                            issuedAt = attestedAttributes.issuedAt,
                            expiresAt = attestedAttributes.expiresAt,
                            notificationId = notificationId,
                            status = attestedAttributes.status,
                            clientStatus = clientStatus.status.statusList,
                            keyStorageStatus = keyStorageStatus,
                        ),
                    )
                    instance
                }.toNonEmptyListOrNull()

        checkNotNull(issuedInstances) { "Cannot happen" }

        return CredentialResponse.Issued(issuedInstances, notificationId)
    }

    private suspend fun statusListToken(expiresAt: Instant): StatusListToken? =
        allocateStatus?.let {
            context(with = it) { allocateStatusWithPolicy(expiresAt) }
        }

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
                encodeAttestationAttributesInMdoc(configuration.docType, issuerSigningKey, usage = usage),
            )
    }
}
