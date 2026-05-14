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
import arrow.core.serialization.NonEmptyListSerializer
import arrow.core.toNonEmptyListOrNull
import arrow.core.toNonEmptyListOrThrow
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL
import kotlin.collections.isNotEmpty
import kotlin.collections.mapIndexed
import kotlin.time.Instant

data class KeyAttestationJWT private constructor(
    val jwt: SignedJWT,
    val keyAttestationClaims: KeyAttestationClaims,
) {
    companion object {
        operator fun invoke(value: String): KeyAttestationJWT = KeyAttestationJWT(SignedJWT.parse(value))

        operator fun invoke(jwt: SignedJWT): KeyAttestationJWT {
            with(jwt) {
                ensureSignedWithSupportedAlgorithm()
                ensureCorrectHeaderType()
                ensureValidIssueTime()
            }

            val attestedKeys = jwt.extractAttestedKeys()
            val keyStorage = jwt.extractKeyStorage()
            val userAuthentication = jwt.extractUserAuthentication()
            val certification = jwt.extractCertification()
            val keyStorageStatus = jwt.extractKeyStorageStatus()
            val status = jwt.extractStatus()
            val nonce = jwt.extractNonce()

            val attestationClaims = KeyAttestationClaims(
                attestedKeys = attestedKeys,
                keyStorage = keyStorage,
                nonce = nonce,
                userAuthentication = userAuthentication,
                certification = certification,
                keyStorageStatus = keyStorageStatus,
                status = status,
            )

            return KeyAttestationJWT(jwt, attestationClaims)
        }
    }
}

private fun SignedJWT.ensureCorrectHeaderType() =
    require(header.type != null && (header.type.type == OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE)) {
        "Invalid Key Attestation JWT. Type must be set to `${OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE}`"
    }
private fun SignedJWT.ensureValidIssueTime() =
    requireNotNull(jwtClaimsSet.issueTime) { "Invalid Key Attestation JWT. Misses `iat` claim" }

private fun SignedJWT.ensureSignedWithSupportedAlgorithm() {
    check(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
    requireSupportedKeyAttestationAlgorithm(header.algorithm)
}

private fun SignedJWT.extractNonce(): String? = jwtClaimsSet.getStringClaim(OpenId4VciSpec.NONCE)
private fun SignedJWT.extractKeyStorage(): NonEmptyList<AttackPotentialResistance>? =
    jwtClaimsSet.getListClaim(OpenId4VciSpec.KEY_ATTESTATION_KEY_STORAGE)?.map {
        require(it is String) {
            "Invalid Key Attestation JWT. 'key_storage' items must be strings"
        }
        AttackPotentialResistance(it)
    }?.toNonEmptyListOrThrow()

private fun SignedJWT.extractUserAuthentication(): NonEmptyList<AttackPotentialResistance>? =
    jwtClaimsSet.getListClaim(OpenId4VciSpec.KEY_ATTESTATION_USER_AUTHENTICATION)?.map {
        require(it is String) {
            "Invalid Key Attestation JWT. 'user_authentication' items must be strings"
        }
        AttackPotentialResistance(it)
    }?.toNonEmptyListOrThrow()

private fun SignedJWT.extractCertification(): StringUrl {
    val certificationClaim = jwtClaimsSet.getStringClaim(OpenId4VciSpec.CERTIFICATION)
    require(certificationClaim.isNotBlank()) {
        "Invalid Key Attestation JWT. 'certification' items must be url"
    }
    val certification = StringUrl(certificationClaim)
    return certification
}

private fun SignedJWT.extractKeyStorageStatus(): KeyStorageStatus =
    jwtClaimsSet.getJSONObjectClaim(TS3.KEY_STORAGE_STATUS).let { keyStorageJsonObject ->
        val keyStorageStatusClaim = JSONObjectUtils.toJSONString(requireNotNull(keyStorageJsonObject))
        jsonSupport.decodeFromString<KeyStorageStatus>(keyStorageStatusClaim)
    }
private fun SignedJWT.extractStatus(): Status =
    jwtClaimsSet.getJSONObjectClaim(TokenStatusListSpec.STATUS).let { statusJsonObject ->
        val statusClaim = JSONObjectUtils.toJSONString(requireNotNull(statusJsonObject))
        jsonSupport.decodeFromString<Status>(statusClaim)
    }

private fun SignedJWT.extractAttestedKeys(): NonEmptyList<JWK> {
    val attestedKeysClaimEntries = jwtClaimsSet.getListClaim(OpenId4VciSpec.KEY_ATTESTATION_ATTESTED_KEYS)
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
    return attestedKeys
}

private fun requireSupportedKeyAttestationAlgorithm(alg: JWSAlgorithm) =
    require(alg in TS3.SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS) {
        "Key Attestation algorithm '${alg.name}' is not supported, must be one of: " +
            TS3.SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS.joinToString(", ") { it.name }
    }

@Serializable
data class KeyAttestationClaims(
    @Required @Serializable(with = JWKNonEmptyListSerializer::class) @SerialName(OpenId4VciSpec.KEY_ATTESTATION_ATTESTED_KEYS)
    val attestedKeys: NonEmptyList<JWK>,
    @Required @Serializable(with = NonEmptyListSerializer::class) @SerialName(OpenId4VciSpec.KEY_ATTESTATION_KEY_STORAGE)
    val keyStorage: NonEmptyList<AttackPotentialResistance>?,
    @Required @Serializable(with = NonEmptyListSerializer::class) @SerialName(OpenId4VciSpec.KEY_ATTESTATION_USER_AUTHENTICATION)
    val userAuthentication: NonEmptyList<AttackPotentialResistance>?,
    @Required @SerialName(OpenId4VciSpec.CERTIFICATION) val certification: StringUrl,
    @SerialName(OpenId4VciSpec.NONCE) val nonce: Nonce? = null,
    @SerialName(TokenStatusListSpec.STATUS) val status: Status? = null,
    @Required @SerialName(TS3.KEY_STORAGE_STATUS)
    val keyStorageStatus: KeyStorageStatus,
)

@Serializable
data class KeyStorageStatus(
    @Required
    @SerialName(TokenStatusListSpec.STATUS)
    val status: Status,
    @Required
    @SerialName(RFC7519.EXPIRES_AT)
    val exp: EpochSecondsInstant,
)

@Serializable
data class Status(
    @Required @SerialName(TokenStatusListSpec.STATUS_LIST) val statusList: StatusListToken,
)

typealias EpochSecondsInstant =
    @Serializable(with = InstantLongSerializer::class)
    Instant
typealias StringUrl =
    @Serializable(with = UrlStringSerializer::class)
    URL
typealias Nonce = String
