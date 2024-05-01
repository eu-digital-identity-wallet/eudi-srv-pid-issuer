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
package eu.europa.ec.eudi.pidissuer.adapter.out

import COSE.AlgorithmID
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertChainUtils
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider

data class IssuerSigningKey(val key: ECKey, val algorithm: JWSAlgorithm) {
    init {
        require(key.isPrivate) { "a private key is required for signing" }
        require(!key.keyID.isNullOrBlank()) { "issuer key must have kid" }
        require(!key.x509CertChain.isNullOrEmpty()) { "issuer key must have an x5c certificate chain" }
        require(algorithm in JWSAlgorithm.Family.EC) { "signing algorithm must be an EC algorithm" }
    }
}

internal fun IssuerSigningKey.cryptoProvider(): SimpleCOSECryptoProvider {
    fun JWSAlgorithm.asAlgorithmId(): AlgorithmID =
        when (this) {
            JWSAlgorithm.ES256 -> AlgorithmID.ECDSA_256
            JWSAlgorithm.ES384 -> AlgorithmID.ECDSA_384
            JWSAlgorithm.ES512 -> AlgorithmID.ECDSA_512
            else -> error("Unsupported JWSAlgorithm $this")
        }
    return SimpleCOSECryptoProvider(
        listOf(
            COSECryptoProviderKeyInfo(
                keyID = key.keyID,
                algorithmID = algorithm.asAlgorithmId(),
                publicKey = key.toECPublicKey(),
                privateKey = key.toECPrivateKey(),
                x5Chain = X509CertChainUtils.parse(key.x509CertChain),
                trustedRootCAs = emptyList(),
            ),
        ),
    )
}
