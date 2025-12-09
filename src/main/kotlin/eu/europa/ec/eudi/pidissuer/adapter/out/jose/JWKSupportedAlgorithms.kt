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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey

val ECKey.supportedJWEAlgorithms: Set<JWEAlgorithm>
    get() = ECDHEncrypter.SUPPORTED_ALGORITHMS

val ECKey.supportedEncryptionMethods: Set<EncryptionMethod>
    get() = ECDHEncrypter.SUPPORTED_ENCRYPTION_METHODS

val RSAKey.supportedJWEAlgorithms: Set<JWEAlgorithm>
    get() = RSAEncrypter.SUPPORTED_ALGORITHMS

val RSAKey.supportedEncryptionMethods: Set<EncryptionMethod>
    get() = RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS

val JWK.supportedEncryptionMethods: Set<EncryptionMethod>
    get() = when (this) {
        is ECKey -> supportedEncryptionMethods
        is RSAKey -> supportedEncryptionMethods
        else -> emptySet()
    }
