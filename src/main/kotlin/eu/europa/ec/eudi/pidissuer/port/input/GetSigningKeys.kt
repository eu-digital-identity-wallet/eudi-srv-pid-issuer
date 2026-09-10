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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.NonEmptyList
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import java.security.cert.X509Certificate

/**
 * Use case that returns all active signing keys, each identified by its vct and
 * represented by its full certificate chain (leaf + root) in PEM.
 */
class GetSigningKeys(
    private val signingKeys: Map<SdJwtVcType, NonEmptyList<X509Certificate>?>,
) {
    operator fun invoke(identifier: String): String? {
        val certificateChain =
            signingKeys
                .filter { it.key.value == identifier }
                .values
                .firstOrNull()

        return certificateChain?.toPem()
    }
}

private fun NonEmptyList<X509Certificate>.toPem(): String =
    joinToString(separator = "\n") { cert ->
        X509CertUtils.toPEMString(cert)
    }
