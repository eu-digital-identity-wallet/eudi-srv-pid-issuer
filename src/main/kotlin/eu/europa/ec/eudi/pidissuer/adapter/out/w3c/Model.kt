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
package eu.europa.ec.eudi.pidissuer.adapter.out.w3c

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.*
import java.net.URI
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

const val TYPE_VerifiableCredential = "VerifiableCredential"
const val CONTEXT_CREDENTIAL = "https://www.w3.org/2018/credentials/v1"
val DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

@JvmInline
value class ID private constructor(val value: URI) {

    override fun toString(): String = value.toString()

    companion object {
        operator fun invoke(value: String): ID = ID(URI.create(value))
    }
}

typealias Claim = Pair<String, JsonElement>
typealias Context = List<URI>

sealed interface Issuer {

    override fun toString(): String

    class ByURI private constructor(
        val value: URI,
    ) : Issuer {

        override fun toString(): String = value.toString()

        companion object {
            operator fun invoke(value: String): ByURI = ByURI(URI.create(value))
        }
    }

    data class ByID(
        val id: URI,
        val info: List<Pair<String, String>>? = null,
    ) : Issuer {

        override fun toString(): String = id.toString()
    }
}

class Type private constructor(
    val elements: List<URI>,
) {
    companion object {
        operator fun invoke(vararg value: String): Type {
            val input = value.asList()
            require(input.isNotEmpty())
            val elements = input.map { URI.create(it) }
            return Type(elements)
        }
    }
}

data class CredentialMetadata(
    val id: ID? = null,
    val type: Type,
    val issuer: Issuer,
    val issuanceDate: Instant,
    val expirationDate: Instant? = null,
    val status: CredentialStatus? = null,
) {
    init {
        require(type.elements.asStrings().contains(TYPE_VerifiableCredential)) { "Credential type must be specified." }
    }
}

data class CredentialStatus(
    val id: ID,
    val type: Type,
)

data class CredentialSubject(
    val id: ID?,
    val claims: List<Claim>,
) {
    init {
        require(claims.isNotEmpty()) { "Credential subject claims must be specified." }
    }
}

data class W3CCredential(
    val context: Context,
    val metadata: CredentialMetadata,
    val credentialSubject: List<CredentialSubject>,
) {
    init {
        require(credentialSubject.isNotEmpty())
    }
}

sealed interface ProofMechanism {

    data class JWT(
        val signingKey: JWK,
        val alg: JWSAlgorithm,
    ) : ProofMechanism

    data object DataIntegrity : ProofMechanism
}

sealed interface W3CVerifiableCredential {

    data class JwtVcJson(
        val credential: SignedJWT,
    ) : W3CVerifiableCredential {
        init {
            require(credential.state == JWSObject.State.SIGNED)
        }
    }

    data class JwtVcJsonLd(
        val credential: String,
    ) : W3CVerifiableCredential

    data class LdpVc(
        val credential: String,
    ) : W3CVerifiableCredential
}

fun W3CCredential.toJsonObject(): JsonObject = buildJsonObject {
    put("@context", JsonArray(context.map { JsonPrimitive(it.toString()) }))
    metadata.id?.let {
        put("id", it.toString())
    }
    putJsonArray("type") {
        metadata.type.elements.forEach { add(it.toString()) }
    }
    put("issuer", metadata.issuer.toJsonElement())
    put("issuanceDate", DATETIME_FORMATTER.format(metadata.issuanceDate))
    metadata.expirationDate?.let {
        put("expirationDate", DATETIME_FORMATTER.format(metadata.expirationDate))
    }
    metadata.status?.let { put("credentialStatus", it.toJsonObject()) }

    if (credentialSubject.size == 1) {
        put("credentialSubject", credentialSubject[0].toJsonObject())
    } else {
        putJsonArray("credentialSubject") {
            credentialSubject.forEach { add(it.toJsonObject()) }
        }
    }
}

fun CredentialStatus.toJsonObject(): JsonObject = buildJsonObject {
    put("id", JsonPrimitive(id.toString()))
    putJsonArray("type") { type.elements.forEach { add(it.toString()) } }
}

fun CredentialSubject.toJsonObject(): JsonObject = buildJsonObject {
    id?.let {
        put("id", JsonPrimitive(id.toString()))
    }
    claims.forEach { (name, value) -> put(name, value) }
}

fun Issuer.toJsonElement(): JsonElement =
    when (this) {
        is Issuer.ByURI -> JsonPrimitive(value.toString())
        is Issuer.ByID -> buildJsonObject {
            put("id", JsonPrimitive(id.toString()))
            info?.let {
                info.forEach { (name, value) -> put(name, value) }
            }
        }
    }

fun List<URI>.asStrings(): List<String> = map { it.toString() }
