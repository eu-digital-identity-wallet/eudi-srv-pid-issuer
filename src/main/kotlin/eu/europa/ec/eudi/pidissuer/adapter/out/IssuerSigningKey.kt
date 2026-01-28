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
package eu.europa.ec.eudi.pidissuer.adapter.out

import COSE.AlgorithmID
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.CoseAlgorithm
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwtFactory
import eu.europa.ec.eudi.sdjwt.SdJwtIssuer
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import java.security.cert.X509Certificate

@JvmInline
value class IssuerSigningKey(val key: ECKey) {
    init {
        require(key.isPrivate) { "a private key is required for signing" }
        require(!key.keyID.isNullOrBlank()) { "issuer key must have kid" }
        require(!key.x509CertChain.isNullOrEmpty()) { "issuer key must have an x5c certificate chain" }
    }
}

internal val IssuerSigningKey.signingAlgorithm: JWSAlgorithm
    get() = when (val curve = key.curve) {
        Curve.P_256 -> JWSAlgorithm.ES256
        Curve.P_384 -> JWSAlgorithm.ES384
        Curve.P_521 -> JWSAlgorithm.ES512
        else -> error("Unsupported ECKey Curve '$curve'")
    }

internal val IssuerSigningKey.algorithmId: AlgorithmID
    get() = when (val curve = key.curve) {
        Curve.P_256 -> AlgorithmID.ECDSA_256
        Curve.P_384 -> AlgorithmID.ECDSA_384
        Curve.P_521 -> AlgorithmID.ECDSA_512
        else -> error("Unsupported ECKey Curve '$curve'")
    }

internal val IssuerSigningKey.coseAlgorithm: CoseAlgorithm
    get() = when (val curve = key.curve) {
        Curve.P_256 -> CoseAlgorithm(-7)
        Curve.P_384 -> CoseAlgorithm(-35)
        Curve.P_521 -> CoseAlgorithm(-36)
        else -> error("Unsupported ECKey Curve '$curve'")
    }

internal fun IssuerSigningKey.cryptoProvider(): SimpleCOSECryptoProvider {
    return SimpleCOSECryptoProvider(
        listOf(
            COSECryptoProviderKeyInfo(
                keyID = key.keyID,
                algorithmID = algorithmId,
                publicKey = key.toECPublicKey(),
                privateKey = key.toECPrivateKey(),
                x5Chain = X509CertChainUtils.parse(key.x509CertChain),
                trustedRootCAs = emptyList(),
            ),
        ),
    )
}

internal val IssuerSigningKey.certificate: X509Certificate
    get() = X509CertUtils.parse(key.x509CertChain.first().decode())

internal fun IssuerSigningKey.sdJwtVcIssuer(digestsHashAlgorithm: HashAlgorithm): SdJwtIssuer<SignedJWT> {
    val factory = SdJwtFactory(digestsHashAlgorithm)
    val signer = ECDSASigner(key)
    return NimbusSdJwtOps.issuer(factory, signer, signingAlgorithm) {
        type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
        keyID(key.keyID)
        x509CertChain(key.x509CertChain)
    }
}
