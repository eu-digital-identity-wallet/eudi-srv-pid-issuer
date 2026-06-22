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
package eu.europa.ec.eudi.pidissuer.port.out.attestation

import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.either
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import kotlin.time.Instant

interface AttestationIssuer {
    val configuration: CredentialConfiguration

    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    suspend operator fun invoke(request: AuthorizedCredentialRequest): CredentialResponse
}

context(_: Raise<IssueCredentialError>, validateProof: ValidateProof)
suspend fun AttestationIssuer.keyAttestation(
    request: AuthorizedCredentialRequest,
    at: Instant,
): KeyAttestation {
    check(configuration.deviceBinding is DeviceBinding.Required) {
        "Applicable only to credentials with device binding"
    }
    val proof =
        context(configuration) {
            validateProof(request.proof, at)
        }
    ensureNotNull(proof) {
        IssueCredentialError.MissingProof
    }
    return proof
}

context(allocateStatus: AllocateStatus)
suspend fun AttestationIssuer.allocateStatusWithPolicy(expiration: Instant): StatusListToken? {
    val cfg = configuration
    val type =
        when (cfg) {
            is MsoMdocCredentialConfiguration -> cfg.docType
            is SdJwtVcCredentialConfiguration -> cfg.type.value
        }

    return when (val reusePolicy = cfg.reusePolicy) {
        is CredentialReusePolicy.EUDI if reusePolicy.shouldIncludeStatusList -> {
            either { allocateStatus(type, expiration) }.getOrElse { throw it.value }
        }

        CredentialReusePolicy.None -> {
            null
        }

        is CredentialReusePolicy.EUDI -> {
            null
        }
    }
}
