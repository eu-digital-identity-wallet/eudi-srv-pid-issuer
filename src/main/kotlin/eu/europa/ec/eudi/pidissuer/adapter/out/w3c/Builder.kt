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

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.time.Instant

@DslMarker
annotation class W3CCredentialDsl

fun buildCredential(use: CredentialBuilder.() -> Unit): W3CCredential {
    val builder = CredentialBuilder()
    builder.use()
    return builder.build()
}

@W3CCredentialDsl
class CredentialBuilder {

    private var context: MutableList<String> = mutableListOf()
    private var metadata: CredentialMetadata? = null
    private var credentialSubjects: MutableList<CredentialSubject> = mutableListOf()

    fun context(value: String) {
        if (!context.contains(value)) {
            context.add(value)
        }
    }

    fun credentialMetadata(use: CredentialMetadataBuilder.() -> Unit) {
        if (metadata != null) error("Metadata already defined")
        val credentialMetadataBuilder = CredentialMetadataBuilder()
        credentialMetadataBuilder.use()
        metadata = credentialMetadataBuilder.build()
    }

    fun credentialSubject(use: CredentialSubjectBuilder.() -> Unit) {
        val credentialSubjectBuilder = CredentialSubjectBuilder()
        credentialSubjectBuilder.use()
        credentialSubjects.add(credentialSubjectBuilder.build())
    }

    fun build(): W3CCredential {
        requireNotNull(metadata) { "Metadata must not be null." }
        require(credentialSubjects.isNotEmpty()) { "Credential subjects must defined." }
        if (context.isEmpty() || !context.contains(CONTEXT_CREDENTIAL)) {
            context.add(0, CONTEXT_CREDENTIAL)
        }
        return W3CCredential(
            context.map { URI.create(it) },
            metadata!!,
            credentialSubjects,
        )
    }
}

@W3CCredentialDsl
class CredentialSubjectBuilder {

    private var id: ID? = null
    private var claims: MutableList<Claim> = mutableListOf()

    fun addClaim(name: String, value: String) {
        claims.add(name to JsonPrimitive(value))
    }

    fun addClaim(name: String, value: Long) {
        claims.add(name to JsonPrimitive(value))
    }

    fun addClaim(name: String, value: List<String>) {
        claims.add(name to JsonArray(value.map { JsonPrimitive(it) }))
    }

    fun addClaim(name: String, value: JsonObject) {
        claims.add(name to value)
    }

    fun addClaim(name: String, value: JsonElement) {
        claims.add(name to value)
    }

    fun id(s: String) {
        id = ID(s)
    }

    fun build(): CredentialSubject {
        require(claims.isNotEmpty()) { "At least one claim must be defined." }
        return CredentialSubject(id, claims)
    }
}

@W3CCredentialDsl
class CredentialMetadataBuilder {

    private var id: ID? = null
    private val types: MutableList<String> = mutableListOf()
    private var issuerStr: String? = null
    private var issuanceDate: Instant? = null
    private var expirationDate: Instant? = null
    private var status: CredentialStatus? = null

    fun id(s: String) {
        id = ID(s)
    }

    fun issuer(value: String) {
        issuerStr = value
    }

    fun type(value: String) {
        if (!types.contains(value)) {
            types.add(value)
        }
    }

    fun issueDate(value: Instant) {
        issuanceDate = value
    }

    fun expirationDate(value: Instant) {
        expirationDate = value
    }

    fun status(value: CredentialStatus) {
        status = value
    }

    fun build(): CredentialMetadata {
        require(types.isNotEmpty()) { "At least one type must be defined." }
        require(issuerStr != null) { "Issuer must be defined." }
        require(issuanceDate != null) { "Issuance date must be defined." }
        if (types.isEmpty() || !types.contains(TYPE_VerifiableCredential)) {
            types.add(0, TYPE_VerifiableCredential)
        }
        return CredentialMetadata(
            id = id,
            type = Type(*types.toTypedArray()),
            issuer = Issuer.ByURI(issuerStr!!),
            issuanceDate = issuanceDate!!,
            expirationDate = expirationDate,
            status = status,

        )
    }
}
