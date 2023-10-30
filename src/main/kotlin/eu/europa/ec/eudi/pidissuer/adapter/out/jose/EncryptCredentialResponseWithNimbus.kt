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
        val credential = response.credential
            ?.let {
                if (it is JsonPrimitive) {
                    it.content
                } else {
                    JSONObjectUtils.parse(Json.encodeToString(it))
                }
            }

        val header = JWEHeader.Builder(parameters.encryptionAlgorithm, parameters.encryptionMethod)
            .jwk(parameters.encryptionJwk)
            .keyID(parameters.encryptionJwk.keyID)
            .type(JOSEObjectType.JWT)
            .build()

        val claimSet = JWTClaimsSet.Builder()
            .issuer(issuer.externalForm)
            .issueTime(Date.from(clock.instant()))
            .claim("format", response.format)
            .claim("credential", credential)
            .claim("transaction_id", response.transactionId)
            .claim("c_nonce", response.nonce)
            .claim("c_nonce_expires_in", response.nonceExpiresIn)
            .build()

        val jwt = EncryptedJWT(header, claimSet)
        val encrypter =
            when (val jwk = parameters.encryptionJwk) {
                is RSAKey -> RSAEncrypter(jwk)
                is ECKey -> ECDHEncrypter(jwk)
                else -> throw IllegalArgumentException("unsupported 'kty': '${jwk.keyType.value}'")
            }

        jwt.encrypt(encrypter)
        jwt.serialize()
    }
}
