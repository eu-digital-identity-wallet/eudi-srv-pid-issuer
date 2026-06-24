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
package eu.europa.ec.eudi.pidissuer.adapter.out.format

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import kotlinx.serialization.json.JsonElement
import kotlin.time.Instant

data class AttestedClaims<out Data>(
    val perInstance: PerInstance,
    val common: Common<Data>,
) {
    data class Common<out Data>(
        val attributes: Data,
        val issuedAt: Instant,
        val expiresAt: Instant,
        val notBefore: Instant? = null,
    ) {
        operator fun plus(instance: PerInstance): AttestedClaims<Data> = AttestedClaims(instance, this)
    }

    data class PerInstance(
        val deviceKey: JWK? = null,
        val status: StatusListToken? = null,
        val jwtId: String? = null,
    ) {
        operator fun <Data> plus(common: Common<Data>): AttestedClaims<Data> = AttestedClaims(this, common)
    }

    companion object {
        fun <Data> partial(common: Common<Data>): (PerInstance) -> AttestedClaims<Data> =
            { instance ->
                AttestedClaims(instance, common)
            }
    }
}

fun interface EncodeAttestationAttributes<in Attr> {
    suspend operator fun invoke(attributes: Attr): JsonElement
}

fun <Attr, Attr1> EncodeAttestationAttributes<Attr>.transform(transform: (Attr1) -> Attr): EncodeAttestationAttributes<Attr1> =
    contraMap(transform)

fun <Attr, Attr1> EncodeAttestationAttributes<Attr>.contraMap(transform: (Attr1) -> Attr): EncodeAttestationAttributes<Attr1> =
    EncodeAttestationAttributesContraMap(this, transform)

private class EncodeAttestationAttributesContraMap<D, D1>(
    private val delegate: EncodeAttestationAttributes<D1>,
    private val f: (D) -> D1,
) : EncodeAttestationAttributes<D> {
    override suspend fun invoke(attributes: D): JsonElement = delegate.invoke(f(attributes))
}
