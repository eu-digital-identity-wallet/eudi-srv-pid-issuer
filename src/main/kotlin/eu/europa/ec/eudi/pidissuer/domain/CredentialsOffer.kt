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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.Ior
import java.time.Duration

/**
 * A
 */
sealed interface CredentialOffer

@JvmInline
value class CredentialOfferByScope(val value: Scope) : CredentialOffer
data class AuthorizationCodeGrant(val issuerState: String? = null)

@JvmInline
value class PreAuthorizedCode(val value: String)
data class PreAuthorizedCodeGrant(
    val preAuthorizedCode: PreAuthorizedCode,
    val userPinRequired: Boolean = false,
    val interval: Duration,
)
typealias Grants = Ior<AuthorizationCodeGrant, PreAuthorizedCodeGrant>

data class CredentialsOffer(
    val credentialIssuer: CredentialIssuerId,
    val grants: Grants,
    val credentials: List<CredentialOffer>,
) {
    companion object {
        fun single(
            credentialIssuer: CredentialIssuerId,
            grants: Grants,
            credentialOffer: CredentialOffer,
        ): CredentialsOffer = CredentialsOffer(
            credentialIssuer,
            grants,
            listOf(credentialOffer),
        )
    }
}
