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
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import java.time.Clock
import java.time.Instant
import java.util.*

/**
 * Implementation of [EncryptCredentialResponse] using Nimbus.
 */
class EncryptCredentialResponseWithNimbus(
    private val issuer: CredentialIssuerId,
    private val clock: Clock,
) : EncryptCredentialResponse {

    override fun invoke(
        response: IssueCredentialResponse.PlainTO,
        parameters: RequestedResponseEncryption.Required,
    ): Result<String> = runCatching {
        val jweHeader = parameters.asHeader()
        val jwtClaimSet = response.asJwtClaimSet(clock.instant())

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

    private fun IssueCredentialResponse.PlainTO.asJwtClaimSet(iat: Instant) =
        JWTClaimsSet.Builder().apply {
            issuer(issuer.externalForm)
            issueTime(Date.from(iat))
            claim("format", format)
            claim(
                "credential",
                credential?.let {
                    if (it is JsonPrimitive) it.content
                    else JSONObjectUtils.parse(Json.encodeToString(it))
                },
            )
            claim("transaction_id", transactionId)
            claim("c_nonce", nonce)
            claim("c_nonce_expires_in", nonceExpiresIn)
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
