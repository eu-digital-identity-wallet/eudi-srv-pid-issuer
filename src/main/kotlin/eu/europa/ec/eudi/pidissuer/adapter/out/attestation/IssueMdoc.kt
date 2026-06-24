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
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.encodeAttestationAttributesInMdoc
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
import kotlinx.serialization.json.JsonElement
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
        val deviceKeys =
            keyAttestation.credentialKeys.value
                .map { jwk -> jwk.toECKeyOrFail { InvalidProof("Only EC Key is supported") } }

        val cmnAttr =
            cmnAttr(
                issuedAt = issuedAt,
                expiresAt = issuedAt + configuration.validity,
                notBefore = null,
                keyAttestation,
            )

        val issuedInstances =
            deviceKeys
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    issueInstance(deviceKey, cmnAttr)
                }.toNonEmptyListOrNull()

        checkNotNull(issuedInstances) { "Cannot happen" }

        return CredentialResponse.Issued(issuedInstances, cmnAttr.notificationId)
    }

    context(_: Raise<IssueCredentialError.AttestationDatasetNotFound>, authorizationContext: AuthorizationContext)
    private suspend fun cmnAttr(
        issuedAt: Instant,
        expiresAt: Instant,
        notBefore: Instant?,
        keyAttestation: KeyAttestation?,
    ): CmnAttr<Attr> {
        val attributes = getAttestationAttributes()
        val notificationId = generateNotificationId?.invoke()
        val clientStatus = authorizationContext.clientStatus
        val keyStorageStatus = keyAttestation?.keyStorageStatus?.status?.statusList
        return CmnAttr(attributes, issuedAt, expiresAt, notBefore, clientStatus, keyStorageStatus, notificationId)
    }

    private suspend fun issueInstance(
        deviceKey: ECKey,
        cmnAttr: CmnAttr<Attr>,
    ): JsonElement {
        val status = statusListToken(cmnAttr.expiresAt)
        val attestedAttributes = cmnAttr.instance(deviceKey, status, jwtId = null)
        val attestationInstance = encodeAttestationAttributes(attestedAttributes).also { log.info("Issued $it") }
        cmnAttr.store(status)
        return attestationInstance
    }

    private suspend fun CmnAttr<Attr>.store(status: StatusListToken?) {
        val issued =
            IssuedCredential(
                format = MSO_MDOC_FORMAT,
                type = configuration.docType,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                notificationId = notificationId,
                status = status,
                clientStatus = clientStatus.status.statusList,
                keyStorageStatus = keyStorageStatus,
            )
        storeIssuedCredential(issued)
    }

    private suspend fun statusListToken(expiresAt: Instant): StatusListToken? =
        allocateStatus?.let {
            context(it) {
                allocateStatusWithPolicy(expiresAt)
            }
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

private data class CmnAttr<out Attr>(
    val attributes: Attr,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val notBefore: Instant?,
    val clientStatus: ClientStatus,
    val keyStorageStatus: StatusListToken?,
    val notificationId: NotificationId?,
)

private fun <Attr> CmnAttr<Attr>.instance(
    deviceKey: ECKey,
    status: StatusListToken?,
    jwtId: String?,
): AttestationAttributes<Attr> =
    AttestationAttributes(
        attributes,
        issuedAt,
        expiresAt,
        notBefore,
        deviceKey,
        status,
        jwtId,
    )
