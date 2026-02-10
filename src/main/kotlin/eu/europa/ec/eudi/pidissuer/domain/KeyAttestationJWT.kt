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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch

data class KeyAttestationJWT private constructor(
    val jwt: SignedJWT,
    val attestedKeys: NonEmptyList<JWK>,
    val keyStorage: List<AttackPotentialResistance>?,
    val userAuthentication: List<AttackPotentialResistance>?,
) {
    val nonce: String?
        get() = jwt.jwtClaimsSet.getStringClaim("nonce")

    companion object {
        operator fun invoke(value: String): KeyAttestationJWT = KeyAttestationJWT(SignedJWT.parse(value))

        operator fun invoke(jwt: SignedJWT): KeyAttestationJWT {
            jwt.ensureSignedNotMAC()
            require(jwt.header.type != null && (jwt.header.type.type == OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE)) {
                "Invalid Key Attestation JWT. Type must be set to `${OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE}`"
            }
            requireNotNull(jwt.jwtClaimsSet.issueTime) { "Invalid Key Attestation JWT. Misses `iat` claim" }

            val attestedKeysClaimEntries = jwt.jwtClaimsSet.getListClaim("attested_keys")
            requireNotNull(attestedKeysClaimEntries) { "Invalid Key Attestation JWT. Misses `attested_keys` claim" }
            require(attestedKeysClaimEntries.isNotEmpty()) {
                "Invalid Key Attestation JWT. `attested_keys` claim must not be empty"
            }

            val attestedKeys = attestedKeysClaimEntries.mapIndexed { index, keyObject ->
                require(keyObject is Map<*, *>) {
                    "Invalid Key Attestation JWT. Item at index $index in `attested_keys` is not a JSON object."
                }
                try {
                    @Suppress("UNCHECKED_CAST")
                    val jwk = JWK.parse(keyObject as Map<String, Any>)
                    require(!jwk.isPrivate) {
                        "Invalid Key Attestation JWT. Item at index $index in `attested_keys` must be a public key."
                    }
                    jwk
                } catch (e: Exception) {
                    throw IllegalArgumentException(
                        "Invalid Key Attestation JWT. Item at index $index in `attested_keys` is not a valid JWK: ${e.message}",
                        e,
                    )
                }
            }.toNonEmptyListOrNull() ?: error("Invalid Key Attestation JWT. `attested_keys` cannot be empty")

            val keyStorage = jwt.jwtClaimsSet.getListClaim("key_storage")?.map {
                require(it is String) {
                    "Invalid Key Attestation JWT. 'key_storage' items must be strings"
                }
                AttackPotentialResistance(it)
            }

            val userAuthentication = jwt.jwtClaimsSet.getListClaim("user_authentication")?.map {
                require(it is String) {
                    "Invalid Key Attestation JWT. 'user_authentication' items must be strings"
                }
                AttackPotentialResistance(it)
            }

            return KeyAttestationJWT(jwt, attestedKeys, keyStorage, userAuthentication)
        }
    }
}

private fun SignedJWT.ensureSignedNotMAC() {
    check(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
    val alg = requireNotNull(header.algorithm) { "Invalid JWT misses header alg" }
    requireIsNotMAC(alg)
}

private fun requireIsNotMAC(alg: JWSAlgorithm) =
    require(!alg.isMACSigning()) { "MAC signing algorithm not allowed" }

private fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS

internal suspend fun List<JWK>.signingKeyOf(signedJwt: SignedJWT): JWK? {
    val tasks = map { jwk: JWK ->
        suspend { verifiesSignature(jwk, signedJwt) }
    }
    return signatureVerifiedByKey(*tasks.toTypedArray())
}

internal fun verifiesSignature(jwk: JWK, signedJwt: SignedJWT): JWK? =
    try {
        val verifier = when (jwk) {
            is RSAKey -> RSASSAVerifier(jwk)
            is ECKey -> ECDSAVerifier(jwk)
            else -> null
        }
        if (verifier != null && signedJwt.verify(verifier)) jwk
        else null
    } catch (_: Exception) {
        null
    }

internal suspend fun signatureVerifiedByKey(vararg tasks: suspend () -> JWK?): JWK? =
    channelFlow {
        tasks.forEach {
            launch { send(it()) }
        }
    }.firstOrNull { it != null }
