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
@file:UseSerializers(NonEmptyListSerializer::class)

package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptyList
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import arrow.core.serialization.NonEmptyListSerializer
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.json.ECKeyJsonObjectSerializer
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

data class KeyAttestationJWT private constructor(
    val jwt: SignedJWT,
    val claims: KeyAttestationClaims,
) {
    companion object {
        context(_: Raise<String>)
        operator fun invoke(value: String): KeyAttestationJWT = KeyAttestationJWT(SignedJWT.parse(value))

        context(_: Raise<String>)
        operator fun invoke(jwt: SignedJWT): KeyAttestationJWT {
            jwt.ensureSignedWithSupportedAlgorithm()
            jwt.ensureCorrectHeaderType()
            val deserializedClaims =
                catch(
                    {
                        val serializedClaims = JSONObjectUtils.toJSONString(jwt.jwtClaimsSet.toJSONObject())
                        jsonSupport.decodeFromString<KeyAttestationClaims>(serializedClaims)
                    },
                ) { _ -> raise("Invalid Key Attestation JWT") }

            return KeyAttestationJWT(jwt, deserializedClaims)
        }
    }
}

context(_: Raise<String>)
private fun SignedJWT.ensureCorrectHeaderType() =
    ensure(header.type != null && (header.type.type == OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE)) {
        "Invalid Key Attestation JWT. Type must be set to `${OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE}`"
    }

context(_: Raise<String>)
private fun SignedJWT.ensureSignedWithSupportedAlgorithm() {
    ensure(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
    requireSupportedKeyAttestationAlgorithm(header.algorithm)
}

context(_: Raise<String>)
private fun requireSupportedKeyAttestationAlgorithm(alg: JWSAlgorithm) =
    ensure(alg in TS3.SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS) {
        "Key Attestation algorithm '${alg.name}' is not supported, must be one of: " +
            TS3.SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS.joinToString(", ") { it.name }
    }

@Serializable
data class KeyAttestationClaims(
    @Required @SerialName(RFC7519.ISSUED_AT) val issuedAt: EpochSecondsInstant,
    @Required @SerialName(RFC7519.EXPIRES_AT) val expiresAt: EpochSecondsInstant,
    @Required @SerialName(OpenId4VciSpec.KEY_ATTESTATION_ATTESTED_KEYS) val attestedKeys: AttestedKeys,
    @Required @SerialName(OpenId4VciSpec.KEY_ATTESTATION_KEY_STORAGE)
    val keyStorage: NonEmptyList<AttackPotentialResistance>,
    @Required @SerialName(OpenId4VciSpec.KEY_ATTESTATION_USER_AUTHENTICATION)
    val userAuthentication: NonEmptyList<AttackPotentialResistance>,
    @Required @SerialName(OpenId4VciSpec.CERTIFICATION) val certification: StringUrl,
    @SerialName(OpenId4VciSpec.NONCE) val nonce: Nonce? = null,
    @SerialName(TokenStatusListSpec.STATUS) val status: Status? = null,
    @Required @SerialName(TS3.KEY_STORAGE_STATUS) val keyStorageStatus: KeyStorageStatus,
)

@JvmInline
@Serializable
value class AttestedKeys(
    val value: NonEmptyList<
        @Serializable(with = ECKeyJsonObjectSerializer::class)
        ECKey,
    >,
) {
    init {
        value.forEachIndexed { index, jwk ->
            require(!jwk.isPrivate) {
                "Invalid Attested Keys. Item at index $index must be a public key."
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

typealias Nonce = String
