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
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.json.AttestedKeysSerializer
import eu.europa.ec.eudi.pidissuer.adapter.out.json.InstantEpochSecondsSerializer
import eu.europa.ec.eudi.pidissuer.adapter.out.json.UrlStringSerializer
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL
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

            val keyAttestation = JSONObjectUtils.toJSONString(jwt.jwtClaimsSet.toJSONObject())
            val keyAttestationClaims = jsonSupport.decodeFromString<KeyAttestationClaims>(keyAttestation)

            return KeyAttestationJWT(jwt, keyAttestationClaims)
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

private fun requireSupportedKeyAttestationAlgorithm(alg: JWSAlgorithm) =
    require(alg in TS3.SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS) {
        "Key Attestation algorithm '${alg.name}' is not supported, must be one of: " +
            TS3.SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS.joinToString(", ") { it.name }
    }

@Serializable
data class KeyAttestationClaims(
    @Required @SerialName(OpenId4VciSpec.KEY_ATTESTATION_ATTESTED_KEYS)
    val attestedKeys: AttestedKeys,
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

@JvmInline
@Serializable(with = AttestedKeysSerializer::class)
value class AttestedKeys(val value: NonEmptyList<JWK>) {
    init {
        value.forEachIndexed { index, jwk ->
            require(!jwk.isPrivate) {
                "Invalid Key Attestation JWT. Item at index $index in `attested_keys` must be a public key."
            }
        }
    }
}

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
    @Serializable(with = InstantEpochSecondsSerializer::class)
    Instant
typealias StringUrl =
    @Serializable(with = UrlStringSerializer::class)
    URL
typealias Nonce = String
