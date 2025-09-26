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
package eu.europa.ec.eudi.pidissuer.adapter.out.credential

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse

internal data class NonceEncryptionKey(
    val encryptionKey: ECKey,
    val algorithm: JWEAlgorithm = JWEAlgorithm.ECDH_ES,
    val method: EncryptionMethod = EncryptionMethod.XC20P,
) {
    init {
        require(encryptionKey.isPrivate) { "a private key is required for encryption" }
        encryptionKey.keyUse?.let { keyUse ->
            require(KeyUse.ENCRYPTION == keyUse) { "encryption key must have key use 'enc'" }
        }
        require(algorithm in ECDHEncrypter.SUPPORTED_ALGORITHMS) {
            "algorithm must be one of ${ECDHEncrypter.SUPPORTED_ALGORITHMS.joinToString(", ") { it.name} }"
        }
        require(method in ECDHEncrypter.SUPPORTED_ENCRYPTION_METHODS) {
            "method must be one of ${ECDHEncrypter.SUPPORTED_ENCRYPTION_METHODS.joinToString(", ") { it.name } }"
        }
    }
}
