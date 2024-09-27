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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.port.input.DeferredCredentialSuccessResponse
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptDeferredResponse
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import java.time.Clock
import java.time.Instant
import java.util.*

/**
 * Converts this [JsonElement] to its Nimbus representation.
 */
private fun JsonElement.toNimbus(): Any =
    when (this) {
        is JsonPrimitive -> content
        else -> JSONObjectUtils.parse(Json.encodeToString(this))
    }

/**
 * Populates either the 'credential' or 'credentials' claim.
 */
private fun JWTClaimsSet.Builder.credentialOrCredentials(
    credential: JsonElement? = null,
    credentials: JsonArray? = null,
) {
    credential?.let {
        val value = it.toNimbus()
        claim("credential", value)
    }
    credentials?.let {
        val value = it.map { credential -> credential.toNimbus() }
        claim("credentials", value)
    }
}

/**
 * Implementation of [EncryptDeferredResponse] using Nimbus.
 */
class EncryptDeferredResponseNimbus(
    issuer: CredentialIssuerId,
    clock: Clock,
) : EncryptDeferredResponse {

    private val encryptResponse = EncryptResponse(issuer, clock)

    override fun invoke(
        response: DeferredCredentialSuccessResponse.PlainTO,
        parameters: RequestedResponseEncryption.Required,
    ): Result<DeferredCredentialSuccessResponse.EncryptedJwtIssued> = runCatching {
        fun JWTClaimsSet.Builder.toJwtClaims(plain: DeferredCredentialSuccessResponse.PlainTO) {
            with(plain) {
                credentialOrCredentials(plain.credential, plain.credentials)
                notificationId?.let { claim("notification_id", it) }
            }
        }

        val jwt = encryptResponse(parameters) { toJwtClaims(response) }.getOrThrow()
        DeferredCredentialSuccessResponse.EncryptedJwtIssued(jwt)
    }
}

/**
 * Implementation of [EncryptCredentialResponse] using Nimbus.
 */
class EncryptCredentialResponseNimbus(
    issuer: CredentialIssuerId,
    clock: Clock,
) : EncryptCredentialResponse {

    private val encryptResponse = EncryptResponse(issuer, clock)

    override fun invoke(
        response: IssueCredentialResponse.PlainTO,
        parameters: RequestedResponseEncryption.Required,
    ): Result<IssueCredentialResponse.EncryptedJwtIssued> = kotlin.runCatching {
        fun JWTClaimsSet.Builder.toJwtClaims(plain: IssueCredentialResponse.PlainTO) {
            with(plain) {
                credentialOrCredentials(plain.credential, plain.credentials)
                transactionId?.let { claim("transaction_id", it) }
                claim("c_nonce", nonce)
                claim("c_nonce_expires_in", nonceExpiresIn)
                notificationId?.let { claim("notification_id", it) }
            }
        }

        val jwt = encryptResponse(parameters) { toJwtClaims(response) }.getOrThrow()
        IssueCredentialResponse.EncryptedJwtIssued(jwt)
    }
}

private class EncryptResponse(
    private val issuer: CredentialIssuerId,
    private val clock: Clock,
) {

    operator fun invoke(
        parameters: RequestedResponseEncryption.Required,
        responseAsJwtClaims: JWTClaimsSet.Builder.() -> Unit,
    ): Result<String> = runCatching {
        val jweHeader = parameters.asHeader()
        val jwtClaimSet = asJwtClaimSet(clock.instant(), responseAsJwtClaims)

        EncryptedJWT(jweHeader, jwtClaimSet)
            .apply { encrypt(parameters.encryptionJwk) }
            .serialize()
    }

    private fun RequestedResponseEncryption.Required.asHeader() =
        JWEHeader.Builder(encryptionAlgorithm, encryptionMethod).apply {
            jwk(encryptionJwk)
            keyID(encryptionJwk.keyID)
            type(JOSEObjectType.JWT)
        }.build()

    private fun asJwtClaimSet(iat: Instant, responseAsJwtClaims: JWTClaimsSet.Builder.() -> Unit) =
        JWTClaimsSet.Builder().apply {
            issuer(issuer.externalForm)
            issueTime(Date.from(iat))
            this.responseAsJwtClaims()
        }.build()

    private fun EncryptedJWT.encrypt(jwk: JWK) {
        val enc = when (jwk) {
            is RSAKey -> RSAEncrypter(jwk)
            is ECKey -> ECDHEncrypter(jwk)
            else -> null
        }
        enc?.let { encrypt(it) }
            ?: error("unsupported 'kty': '${jwk.keyType.value}'")
    }
}
