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
package eu.europa.ec.eudi.pidissuer.port.out.trust

import arrow.core.NonEmptyList
import kotlinx.serialization.Serializable
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

sealed interface TrustResult {
    data class IsTrusted(
        val trustAnchor: TrustAnchor,
    ) : TrustResult

    object IsUntrusted : TrustResult
}

@Serializable
enum class VerificationContext {
    WalletProviderAttestation,
    WalletOrKeyStorageStatus,
}

fun interface IsTrustedIssuer {
    suspend operator fun invoke(
        x5c: NonEmptyList<X509Certificate>,
        verificationContext: VerificationContext,
    ): TrustResult

    companion object
}
