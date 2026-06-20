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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.Either
import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptDeferredResponse
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialByTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.LoadDeferredCredentialResult
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

class GetDeferredCredentialTest {
    private val credentialConfiguration =
        pidMsoMdocV1(
            credentialSigningAlgorithm = CoseAlgorithm(-7),
            deviceBinding =
                DeviceBinding.Required(
                    nonEmptySetOf(JWSAlgorithm.ES256),
                    KeyAttestationRequirement.ts3(
                        PreferredKeyStorageStatusPeriod(60.days),
                    ),
                ),
        )

    private val attestationIssuer =
        object : AttestationIssuer {
            override val supportedCredential: CredentialConfiguration = credentialConfiguration
            override val publicKey = null
            override val validity = 365.days

            context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
            override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse =
                throw UnsupportedOperationException("Not expected in this test")
        }

    private val encryptDeferredResponse =
        object : EncryptDeferredResponse {
            override suspend fun invoke(
                response: IssuedTO,
                parameters: RequestedResponseEncryption.Required,
            ): EncryptedJWT = throw UnsupportedOperationException("Not expected in this test")

            override suspend fun invoke(
                response: IssuancePendingTO,
                parameters: RequestedResponseEncryption.Required,
            ): EncryptedJWT = throw UnsupportedOperationException("Not expected in this test")
        }

    private fun metadata(credentialRequestEncryption: CredentialRequestEncryption = CredentialRequestEncryption.NotSupported) =
        CredentialIssuerMetaData(
            id = HttpsUrl.unsafe("https://issuer.example.com"),
            authorizationServers = listOf(HttpsUrl.unsafe("https://auth.example.com")),
            credentialEndPoint = HttpsUrl.unsafe("https://issuer.example.com/credential"),
            batchCredentialIssuance = BatchCredentialIssuance.Supported(batchSize = 3),
            credentialRequestEncryption = credentialRequestEncryption,
            credentialResponseEncryption = CredentialResponseEncryption.NotSupported,
            attestationIssuers = nonEmptyListOf(attestationIssuer),
            preferredClientStatusPeriod = PreferredClientStatusPeriod(400.days),
        )

    @Test
    fun `poll issuance pending returns issuance pending response`() =
        runTest {
            val loadDeferred =
                LoadDeferredCredentialByTransactionId {
                    LoadDeferredCredentialResult.IssuancePending(
                        CredentialResponse.Deferred(
                            transactionId = TransactionId("deferred-tx-1"),
                            interval = 5.seconds,
                        ),
                    )
                }
            val getDeferred =
                GetDeferredCredential(
                    loadDeferredCredentialByTransactionId = loadDeferred,
                    encryptCredentialResponse = encryptDeferredResponse,
                    credentialIssuerMetadata = metadata(),
                )

            val result =
                getDeferred.fromPlainRequest(
                    DeferredCredentialRequestTO(transactionId = "deferred-tx-1"),
                )

            val pending = assertIs<DeferredCredentialResponse.IssuancePending>(result)
            when (val content = pending.content) {
                is Either.Left -> {
                    assertEquals("deferred-tx-1", content.value.transactionId)
                    assertEquals(5L, content.value.interval)
                }

                is Either.Right -> {
                    throw AssertionError("Expected plain response but got encrypted")
                }
            }
        }

    @Test
    fun `poll credential ready returns issued response`() =
        runTest {
            val loadDeferred =
                LoadDeferredCredentialByTransactionId {
                    LoadDeferredCredentialResult.Found(
                        CredentialResponse.Issued(
                            credentials = nonEmptyListOf(JsonPrimitive("test-credential")),
                            notificationId = NotificationId("notif-1"),
                        ),
                    )
                }
            val getDeferred =
                GetDeferredCredential(
                    loadDeferredCredentialByTransactionId = loadDeferred,
                    encryptCredentialResponse = encryptDeferredResponse,
                    credentialIssuerMetadata = metadata(),
                )

            val result =
                getDeferred.fromPlainRequest(
                    DeferredCredentialRequestTO(transactionId = "deferred-tx-1"),
                )

            val issued = assertIs<DeferredCredentialResponse.Issued>(result)
            when (val content = issued.content) {
                is Either.Left -> {
                    assertEquals(1, content.value.credentials.size)
                    assertEquals(
                        "test-credential",
                        content.value.credentials
                            .single()
                            .value["credential"]
                            ?.let { it as? JsonPrimitive }
                            ?.content,
                    )
                    assertEquals("notif-1", content.value.notificationId)
                }

                is Either.Right -> {
                    throw AssertionError("Expected plain response but got encrypted")
                }
            }
        }

    @Test
    fun `poll invalid transaction id returns failed response`() =
        runTest {
            val loadDeferred =
                LoadDeferredCredentialByTransactionId {
                    LoadDeferredCredentialResult.InvalidTransactionId
                }
            val getDeferred =
                GetDeferredCredential(
                    loadDeferredCredentialByTransactionId = loadDeferred,
                    encryptCredentialResponse = encryptDeferredResponse,
                    credentialIssuerMetadata = metadata(),
                )

            val result =
                getDeferred.fromPlainRequest(
                    DeferredCredentialRequestTO(transactionId = "unknown-tx"),
                )

            val failed = assertIs<DeferredCredentialResponse.Failed>(result)
            assertEquals(GetDeferredCredentialErrorTypeTo.INVALID_TRANSACTION_ID, failed.content.type)
        }

    @Test
    fun `plain request when encryption required returns invalid credential request`() =
        runTest {
            val encryptionKey =
                ECKeyGenerator(Curve.P_256)
                    .keyID("test-kid")
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate()
            val encryptionParams =
                CredentialRequestEncryptionSupportedParameters(
                    encryptionKeys = JWKSet(listOf(encryptionKey)),
                    methodsSupported = nonEmptySetOf(EncryptionMethod.A128CBC_HS256),
                    zipAlgorithmsSupported = null,
                )
            val getDeferred =
                GetDeferredCredential(
                    loadDeferredCredentialByTransactionId = {
                        throw UnsupportedOperationException("Should not be called")
                    },
                    encryptCredentialResponse = encryptDeferredResponse,
                    credentialIssuerMetadata =
                        metadata(
                            credentialRequestEncryption = CredentialRequestEncryption.Required(encryptionParams),
                        ),
                )

            val result =
                getDeferred.fromPlainRequest(
                    DeferredCredentialRequestTO(transactionId = "any"),
                )

            val failed = assertIs<DeferredCredentialResponse.Failed>(result)
            assertEquals(GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, failed.content.type)
        }

    @Test
    fun `encrypted request when encryption not supported returns invalid credential request`() =
        runTest {
            var loadCalled = false
            val loadDeferred =
                LoadDeferredCredentialByTransactionId {
                    loadCalled = true
                    LoadDeferredCredentialResult.InvalidTransactionId
                }
            val getDeferred =
                GetDeferredCredential(
                    loadDeferredCredentialByTransactionId = loadDeferred,
                    encryptCredentialResponse = encryptDeferredResponse,
                    credentialIssuerMetadata = metadata(),
                )

            val result = getDeferred.fromEncryptedRequest("any-jwt")

            val failed = assertIs<DeferredCredentialResponse.Failed>(result)
            assertEquals(GetDeferredCredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, failed.content.type)
            assertTrue(loadCalled.not(), "load should not be called when decryption fails")
        }
}
