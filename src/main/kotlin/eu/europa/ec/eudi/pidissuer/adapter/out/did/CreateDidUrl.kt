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
package eu.europa.ec.eudi.pidissuer.adapter.out.did

import arrow.core.raise.result
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import foundation.identity.did.DIDURL
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.erwinkok.multiformat.multibase.Multibase
import org.erwinkok.multiformat.multicodec.Multicodec
import org.erwinkok.multiformat.util.writeUnsignedVarInt
import java.io.ByteArrayOutputStream

sealed interface DidMethod {
    data object KEY : DidMethod
    data object JWK : DidMethod
}

/**
 * Given a [JWK] key it creates a DIDUrl of did methods
 *
 * * did:key
 * * did:jwk
 *
 */
fun createDidUrl(publicKey: JWK, method: DidMethod): Result<DIDURL> = result {
    when (method) {
        DidMethod.KEY -> createDidKey(publicKey)
        DidMethod.JWK -> createDidJwk(publicKey)
    }
}

private val supportedEcKeyCurves = setOf(
    Curve.X25519,
    Curve.Ed25519,
    Curve.SECP256K1,
    Curve.P_256,
    Curve.P_384,
    Curve.P_521,
)

/**
 * did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
 */
private fun createDidKey(key: JWK): DIDURL = when (key) {
    is RSAKey -> createFromRSAPublicKey(key)
    is ECKey -> createFromECPublicKey(key)
    is OctetKeyPair -> createFromOctet(key)
    else -> error("Unsupported key type")
}

private fun createFromRSAPublicKey(key: RSAKey): DIDURL {
    val instance = SubjectPublicKeyInfo.getInstance(key.toKeyPair().public.encoded)
    val keyBytes = instance.publicKeyData.bytes
    return keyBytes.didUrl(Multicodec.RSA_PUB)
}

private fun createFromECPublicKey(key: ECKey): DIDURL {
    val curve = key.curve
    require(curve in supportedEcKeyCurves) { "Unsupported EC key curve $curve" }
    val compressed = EC5Util.convertPoint(key.toECPublicKey().params, key.toECPublicKey().w).getEncoded(true)
    return compressed.didUrl(curve.multiCodec())
}

fun createFromOctet(key: OctetKeyPair): DIDURL {
    val curve = key.curve
    require(curve in supportedEcKeyCurves) { "Unsupported Octet key curve $curve" }
    val keyBytes = key.toPublicJWK().decodedX
    return keyBytes.didUrl(curve.multiCodec())
}

private fun ByteArray.didUrl(codec: Multicodec): DIDURL {
    val byteArrayOutputStream = ByteArrayOutputStream()
    val bytes = byteArrayOutputStream.use { stream ->
        stream.writeUnsignedVarInt(codec.code)
        stream.writeBytes(this)
        stream.toByteArray()
    }
    val base58BTCEncoded = Multibase.BASE58_BTC.encode(bytes)
    return DIDURL.fromString("did:key:$base58BTCEncoded")
}

private fun Curve.multiCodec(): Multicodec = when (this) {
    Curve.SECP256K1 -> Multicodec.SECP256K1_PUB
    Curve.P_256 -> Multicodec.P256_PUB
    Curve.P_384 -> Multicodec.P384_PUB
    Curve.P_521 -> Multicodec.P521_PUB
    Curve.Ed25519 -> Multicodec.ED25519_PUB
    Curve.X25519 -> Multicodec.X25519_PUB
    else -> error("Unsupported curve: $this")
}

private fun createDidJwk(key: JWK): DIDURL {
    val encoded = Base64URL.encode(
        key.toPublicJWK().toJSONString(),
    )
    return DIDURL.fromString("did:jwk:$encoded")
}
