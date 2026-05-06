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

import eu.europa.ec.eudi.sdjwt.RFC7519
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

@Serializable
data class ClientStatus(
    @Required @SerialName(TokenStatusListSpec.STATUS) val status: StatusClaim,
    @Required @SerialName(RFC7519.EXPIRATION_TIME) @Serializable(with = NumericInstantSerializer::class) val expiresAt: Instant,
)

@Serializable
data class StatusClaim(
    @Required @SerialName(TokenStatusListSpec.STATUS_LIST) val statusList: StatusListTokenClaim,
)

@Serializable
data class StatusListTokenClaim(
    @Required @SerialName(TokenStatusListSpec.IDX) val index: UInt,
    @Required @SerialName(TokenStatusListSpec.URI) val uri: NonBlankString,
)

object NumericInstantSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("NumericInstant", PrimitiveKind.LONG)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeLong(value.epochSeconds)
    }

    override fun deserialize(decoder: Decoder): Instant {
        return Instant.fromEpochSeconds(decoder.decodeLong())
    }
}
