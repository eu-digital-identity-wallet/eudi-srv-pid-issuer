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

import arrow.core.Either
import arrow.core.getOrElse
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

internal class EncryptCredentialResponseWithNimbusTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.System
    private val encrypter = EncryptCredentialResponseNimbus(issuer, clock)
    private val jacksonObjectMapper: ObjectMapper by lazy { jacksonObjectMapper() }

    @Test
    internal fun `encrypt response with RSA`() = runTest {
        val key = RSAKeyGenerator(2048, false)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.RSA_OAEP_256)
            .keyID("rsa-jwt")
            .generate()
        val jwk = key.toPublicJWK()
        val parameters = RequestedResponseEncryption.Required(jwk)
        val unencrypted = IssueCredentialResponse.PlainTO(
            credentials = listOf(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("credential"))),
            transactionId = null,
            notificationId = UUID.randomUUID().toString(),
        )

        encryptAndVerify(unencrypted, parameters, key)
    }

    @Test
    internal fun `encrypt response with ECDH`() = runTest {
        val key = ECKeyGenerator(Curve.P_521)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("ec-jwt")
            .generate()
        val jwk = key.toPublicJWK()
        val parameters = RequestedResponseEncryption.Required(jwk)
        val unencrypted = IssueCredentialResponse.PlainTO(
            credentials = listOf(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("credential"))),
            transactionId = null,
            notificationId = UUID.randomUUID().toString(),
        )

        encryptAndVerify(unencrypted, parameters, key)
    }

    private fun encryptAndVerify(
        unencrypted: IssueCredentialResponse.PlainTO,
        parameters: RequestedResponseEncryption.Required,
        decryptionKey: JWK,
    ) {
        val encrypted = encrypter(unencrypted, parameters).getOrElse { fail(it.message, it) }

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jweTypeVerifier = DefaultJOSEObjectTypeVerifier.JWT
            jweKeySelector = JWEDecryptionKeySelector(
                parameters.encryptionAlgorithm,
                parameters.encryptionMethod,
                ImmutableJWKSet(JWKSet(decryptionKey)),
            )
            jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
                JWTClaimsSet.Builder()
                    .issuer(issuer.externalForm)
                    .apply {
                        unencrypted.transactionId?.let { claim("transaction_id", it) }
                        unencrypted.notificationId?.let { claim("notification_id", it) }
                    }
                    .build(),
                setOf("iat") + (unencrypted.credentials?.let { setOf("credentials") } ?: emptySet()),
            )
        }

        val claims = Either.catch { processor.process(encrypted.jwt, null) }.getOrElse { fail(it.message, it) }
        val credential = claims.getListClaim("credentials")
            ?.let {
                it.map { credential ->
                    when (credential) {
                        is Map<*, *> -> Either.catch {
                            Json.decodeFromString<IssueCredentialResponse.PlainTO.CredentialTO>(
                                jacksonObjectMapper.writeValueAsString(credential),
                            )
                        }.getOrElse { error -> fail(error.message, error) }
                        else -> fail("unexpected type in 'credentials' claim ${credential::class.java}")
                    }
                }
            }

        assertEquals(unencrypted.credentials, credential)
    }
}
