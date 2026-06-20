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
package eu.europa.ec.eudi.pidissuer.port.out.jose

import arrow.core.NonEmptySet
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm

sealed interface RequestEncryptionError {
    data class UnparseableEncryptedRequest(
        val cause: Throwable? = null,
    ) : RequestEncryptionError

    data object RequestEncryptionNotSupported : RequestEncryptionError

    data object RequestEncryptionIsRequired : RequestEncryptionError

    data object ResponseEncryptionRequiresEncryptedRequest : RequestEncryptionError

    data class UnsupportedEncryptionAlgorithm(
        val encryptionAlgorithm: JWEAlgorithm,
        val algorithmsSupported: NonEmptySet<JWEAlgorithm>,
    ) : RequestEncryptionError

    data class UnsupportedEncryptionMethod(
        val encryptionMethod: EncryptionMethod,
        val methodsSupported: NonEmptySet<EncryptionMethod>,
    ) : RequestEncryptionError

    data object RequestCompressionNotSupported : RequestEncryptionError

    data class UnsupportedRequestCompressionMethod(
        val compressionAlgorithm: CompressionAlgorithm,
        val compressionMethodsSupported: NonEmptySet<CompressionAlgorithm>?,
    ) : RequestEncryptionError
}
