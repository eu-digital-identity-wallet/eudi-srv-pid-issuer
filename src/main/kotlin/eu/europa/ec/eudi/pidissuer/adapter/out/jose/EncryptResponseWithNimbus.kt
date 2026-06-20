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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.toJavaDate
import eu.europa.ec.eudi.pidissuer.port.input.IssuancePendingTO
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.input.IssuedTO
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptDeferredResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.time.Clock

/**
 * Implementation of [EncryptDeferredResponse] using Nimbus.
 */
class EncryptDeferredResponseNimbus(
    issuer: CredentialIssuerId,
    clock: Clock,
) : EncryptDeferredResponse {
    private val encryptResponse = EncryptResponse(issuer, clock)

    override suspend fun invoke(
        response: IssuedTO,
        parameters: RequestedResponseEncryption.Required,
    ): EncryptedJWT = encryptResponse(response, parameters)

    override suspend fun invoke(
        response: IssuancePendingTO,
        parameters: RequestedResponseEncryption.Required,
    ): EncryptedJWT = encryptResponse(response, parameters)
}

/**
 * Implementation of [EncryptCredentialResponse] using Nimbus.
 */
class EncryptCredentialResponseNimbus(
    issuer: CredentialIssuerId,
    clock: Clock,
) : EncryptCredentialResponse {
    private val encryptResponse = EncryptResponse(issuer, clock)

    override suspend fun invoke(
        response: IssueCredentialResponse.PlainTO,
        parameters: RequestedResponseEncryption.Required,
    ): IssueCredentialResponse.EncryptedJwtIssued {
        val jwt = encryptResponse(response, parameters)
        return IssueCredentialResponse.EncryptedJwtIssued(jwt.serialize())
    }
}

private class EncryptResponse(
    private val issuer: CredentialIssuerId,
    private val clock: Clock,
) {
    suspend inline operator fun <reified T> invoke(
        response: T,
        parameters: RequestedResponseEncryption.Required,
        noinline customize: JWTClaimsSet.Builder.() -> Unit = {},
    ): EncryptedJWT = invoke(response, parameters, serializer(), customize)

    suspend operator fun <T> invoke(
        response: T,
        parameters: RequestedResponseEncryption.Required,
        serializer: KSerializer<T>,
        customize: JWTClaimsSet.Builder.() -> Unit = {},
    ): EncryptedJWT =
        withContext(Dispatchers.Default) {
            val jweHeader = parameters.asHeader()
            val claimsJson = Json.encodeToString(serializer, response)
            val baseClaims = JWTClaimsSet.parse(claimsJson)
            val jwtClaimSet =
                JWTClaimsSet
                    .Builder(baseClaims)
                    .issuer(issuer.externalForm)
                    .issueTime(clock.now().toJavaDate())
                    .apply(customize)
                    .build()

            EncryptedJWT(jweHeader, jwtClaimSet)
                .apply { encrypt(parameters.encryptionJwk) }
        }

    private fun RequestedResponseEncryption.Required.asHeader() =
        JWEHeader
            .Builder(encryptionAlgorithm, encryptionMethod)
            .apply {
                jwk(encryptionJwk)
                keyID(encryptionJwk.keyID)
                type(JOSEObjectType.JWT)
                compressionAlgorithm?.let {
                    compressionAlgorithm(it)
                }
            }.build()

    private fun EncryptedJWT.encrypt(jwk: JWK) {
        val enc =
            when (jwk) {
                is RSAKey -> RSAEncrypter(jwk)
                is ECKey -> ECDHEncrypter(jwk)
                else -> null
            }
        enc?.let { encrypt(it) }
            ?: error("unsupported 'kty': '${jwk.keyType.value}'")
    }
}
