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
package eu.europa.ec.eudi.pidissuer

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.util.JSONUtils
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec
import eu.europa.ec.eudi.pidissuer.domain.toJavaDate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import java.util.*
import kotlin.test.assertNotNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

internal fun jwtProof(
    audience: CredentialIssuerId,
    clock: Clock,
    nonce: String,
    key: ECKey,
    headerCustomizer: JWSHeader.Builder.() -> Unit = { },
): SignedJWT {
    val header =
        JWSHeader
            .Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID("0")
            .apply(headerCustomizer)
            .build()
    val claims =
        JWTClaimsSet
            .Builder()
            .audience(audience.externalForm)
            .issueTime(clock.now().toJavaDate())
            .claim("nonce", nonce)
            .build()
    val jwt = SignedJWT(header, claims)
    jwt.sign(ECDSASigner(key))

    return jwt
}

internal suspend fun jwtProofWithKeyAttestation(
    clock: Clock,
    audience: CredentialIssuerId,
    nonce: String,
    extraKeysNo: Int = 3,
): SignedJWT {
    val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
    val keyAttestationJwt =
        keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            keyStorageConstraints = listOf("iso_18045_high"),
            userAuthorizationConstraints = listOf("iso_18045_high"),
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

    return jwtProof(audience, clock, nonce, jwtProofSigningKey) {
        customParam("key_attestation", keyAttestationJwt.serialize())
    }
}

/**
 * Creates a key attestation jwt having as attested keys the one passed in [proofSigningKey]
 * plus a number of keys generated from [extraKeys] function.
 *
 * NOTE: The [proofSigningKey] is added first in the array of attested keys.
 *
 * @param proofSigningKey The key used to sign the JWT Proof
 * @param extraKeys   Function that generates the extra keys to be included in the 'attested_keys' array claim.
 */
internal suspend fun keyAttestationJWT(
    proofSigningKey: ECKey,
    keyStorageConstraints: List<String> = listOf("iso_18045_high"),
    userAuthorizationConstraints: List<String> = listOf("iso_18045_high"),
    cNonce: String? = null,
    clock: Clock = Clock.System,
    expiresAt: Instant = clock.now() + 60.days,
    includeExpiresAt: Boolean = true,
    extraKeys: () -> List<ECKey> = { emptyList() },
): SignedJWT {
    val keyAttestationSigningKey = loadECKey("key-attestation-key.pem")
    val signer = ECDSASigner(keyAttestationSigningKey)

    val attestedKeys = listOf(proofSigningKey) + extraKeys()

    val attestedKeysJsonArray =
        attestedKeys.map { key ->
            JSONUtils.parseJSON(key.toPublicJWK().toJSONString())
        }

    val chain = loadChain("key-attestation-chain.pem")
    val encodedChain =
        chain.map {
            com.nimbusds.jose.util.Base64
                .encode(it.encoded)
        }

    val builder = JWTClaimsSet.Builder()
    if (includeExpiresAt) {
        builder.expirationTime(expiresAt.toJavaDate())
    }

    val status =
        mapOf(
            "status_list" to
                mapOf(
                    "idx" to 7656,
                    "uri" to "https://issuer.eudiw.dev/token_status_list/FC/key-attestation+jwt/6923e00d-2d4c-4177-b956-690152f54647",
                ),
        )
    val keyStorageStatus =
        mapOf(
            "status" to status,
            "exp" to expiresAt.epochSeconds,
        )

    val claimsSet =
        builder
            .issueTime(Date())
            .claim("status", status)
            .claim("certification", "https://issuer.eudiw.dev/certification")
            .claim("attested_keys", attestedKeysJsonArray)
            .claim("key_storage", keyStorageConstraints)
            .claim("user_authentication", userAuthorizationConstraints)
            .claim("key_storage_status", keyStorageStatus)
            .claim("nonce", cNonce)
            .build()

    return SignedJWT(
        JWSHeader
            .Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE))
            .x509CertChain(encodedChain)
            .build(),
        claimsSet,
    ).apply { sign(signer) }
}

private suspend fun loadChain(filename: String): NonEmptyList<X509Certificate> =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/$filename")
            .readText()
            .let {
                X509CertChainUtils.parse(it)
            }.let {
                assertNotNull(it.toNonEmptyListOrNull())
            }
    }

private suspend fun loadECKey(filename: String): ECKey =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/$filename")
            .readText()
            .let {
                ECKey.parseFromPEMEncodedObjects(it).toECKey()
            }
    }
