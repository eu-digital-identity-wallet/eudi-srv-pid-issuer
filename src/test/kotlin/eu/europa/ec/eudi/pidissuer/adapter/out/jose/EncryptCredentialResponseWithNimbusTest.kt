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
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import java.time.Clock
import java.time.Duration
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

internal class EncryptCredentialResponseWithNimbusTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.systemDefaultZone()
    private val encrypter = EncryptCredentialResponseNimbus(issuer, clock)

    @Test
    internal fun `encrypt response with RSA`() = runTest {
        val key = RSAKeyGenerator(2048, false)
            .keyUse(KeyUse.ENCRYPTION)
            .keyID("rsa-jwt")
            .generate()
        val jwk = key.toPublicJWK()
        val parameters = RequestedResponseEncryption.Required(jwk, JWEAlgorithm.RSA_OAEP_512)
        val unencrypted = IssueCredentialResponse.PlainTO(
            credential = JsonPrimitive("credential"),
            credentials = null,
            transactionId = null,
            nonce = "nonce",
            Duration.ofMinutes(5L).seconds,
            UUID.randomUUID().toString(),
        )

        encryptAndVerify(unencrypted, parameters, key)
    }

    @Test
    internal fun `encrypt response with ECDH`() = runTest {
        val key = ECKeyGenerator(Curve.P_521)
            .keyUse(KeyUse.ENCRYPTION)
            .keyID("ec-jwt")
            .generate()
        val jwk = key.toPublicJWK()
        val parameters = RequestedResponseEncryption.Required(jwk, JWEAlgorithm.ECDH_ES_A256KW)
        val unencrypted = IssueCredentialResponse.PlainTO(
            credential = JsonPrimitive("credential"),
            credentials = null,
            transactionId = null,
            nonce = "nonce",
            Duration.ofMinutes(5L).seconds,
            UUID.randomUUID().toString(),
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
                        unencrypted.nonce?.let { claim("c_nonce", it) }
                        unencrypted.nonceExpiresIn?.let { claim("c_nonce_expires_in", it) }
                        unencrypted.notificationId?.let { claim("notification_id", it) }
                    }
                    .build(),
                setOf("iat") + (unencrypted.credential?.let { setOf("credential") } ?: emptySet()),
            )
        }

        val claims = runCatching { processor.process(encrypted.jwt, null) }.getOrElse { fail(it.message, it) }
        val credential = claims.getClaim("credential")
            ?.let {
                when (it) {
                    is String -> JsonPrimitive(it)
                    is Map<*, *> -> runCatching {
                        Json.decodeFromString<JsonElement>(Json.encodeToString(it))
                    }.getOrElse { error -> fail(error.message, error) }

                    else -> fail("unexpected 'credential' claim ${it::class.java}")
                }
            }
        assertEquals(unencrypted.credential, credential)
    }
}
