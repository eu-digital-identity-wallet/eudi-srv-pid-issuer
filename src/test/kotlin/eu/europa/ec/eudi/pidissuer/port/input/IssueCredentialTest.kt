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

import arrow.core.NonEmptySet
import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid.PidMsoMdocScope
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid.PidMsoMdocV1CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid.pidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.jwtProof
import eu.europa.ec.eudi.pidissuer.port.out.attestation.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.jose.EncryptCredentialResponse
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

class IssueCredentialTest {
    private val clock = Clock.System
    private val testKey = ECKeyGenerator(Curve.P_256).generate()

    private val msoMdocConfig =
        pidMsoMdocV1(
            credentialSigningAlgorithm = CoseAlgorithm(-7),
            deviceBinding =
                DeviceBinding.Required.ts3(
                    nonEmptySetOf(JWSAlgorithm.ES256),
                    PreferredKeyStorageStatusPeriod(60.days),
                ),
            validity = 60.days,
        )

    private val attestationIssuer =
        object : AttestationIssuer {
            override val configuration: CredentialConfiguration = msoMdocConfig

            context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
            override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse =
                CredentialResponse.Issued(nonEmptyListOf(JsonPrimitive("test-credential")))
        }

    private val metaData =
        CredentialIssuerMetaData(
            id = HttpsUrl.unsafe("https://issuer.example.com"),
            authorizationServers = listOf(HttpsUrl.unsafe("https://auth.example.com")),
            credentialEndPoint = HttpsUrl.unsafe("https://issuer.example.com/credential"),
            batchCredentialIssuance = BatchCredentialIssuance.Supported(batchSize = 3),
            credentialRequestEncryption = CredentialRequestEncryption.NotSupported,
            credentialResponseEncryption = CredentialResponseEncryption.NotSupported,
            attestationIssuers = nonEmptyListOf(attestationIssuer),
            preferredClientStatusPeriod = PreferredClientStatusPeriod(400.days),
        )

    private val encryptCredentialResponse =
        EncryptCredentialResponse { _, _ ->
            IssueCredentialResponse.EncryptedJwtIssued("encrypted-jwt")
        }

    private val issueCredential =
        IssueCredential(
            credentialIssuerMetadata = metaData,
            encryptCredentialResponse = encryptCredentialResponse,
            clock = clock,
        )

    private fun authorizationContext(
        scopes: NonEmptySet<Scope> = nonEmptySetOf(PidMsoMdocScope),
        clientStatusExpiresAt: Instant = clock.now() + 500.days,
    ): AuthorizationContext =
        AuthorizationContext(
            username = "test-user",
            accessToken = DPoPAccessToken("test-token"),
            scopes = scopes,
            clientStatus =
                ClientStatus(
                    status =
                        StatusClaim(
                            statusList =
                                StatusListToken(
                                    statusList = URI.create("https://example.com/issuer-status"),
                                    index = 0u,
                                ),
                        ),
                    expiresAt = clientStatusExpiresAt,
                ),
        )

    private fun jwtProofString(): String = jwtProof(metaData.id, clock, "test-nonce", testKey).serialize()

    @Test
    fun `successful issuance by credential configuration id`() =
        runTest {
            val authContext = authorizationContext()
            val request =
                CredentialRequestTO(
                    credentialConfigurationId = PidMsoMdocV1CredentialConfigurationId.value,
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            assertIs<IssueCredentialResponse.PlainTO>(result)
        }

    @Test
    fun `fails when both identifiers missing`() =
        runTest {
            val authContext = authorizationContext()
            val request =
                CredentialRequestTO(
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            val failed = assertIs<IssueCredentialResponse.FailedTO>(result)
            assertEquals(CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, failed.type)
        }

    @Test
    fun `fails when both identifiers provided`() =
        runTest {
            val authContext = authorizationContext()
            val request =
                CredentialRequestTO(
                    credentialConfigurationId = "some-id",
                    credentialIdentifier = "some-identifier",
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            val failed = assertIs<IssueCredentialResponse.FailedTO>(result)
            assertEquals(CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, failed.type)
        }

    @Test
    fun `fails with unknown credential configuration id`() =
        runTest {
            val authContext = authorizationContext()
            val request =
                CredentialRequestTO(
                    credentialConfigurationId = "unknown-id",
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            val failed = assertIs<IssueCredentialResponse.FailedTO>(result)
            assertEquals(CredentialErrorTypeTo.UNKNOWN_CREDENTIAL_CONFIGURATION, failed.type)
        }

    @Test
    fun `fails with client status expired before preferred period`() =
        runTest {
            val authContext =
                authorizationContext(
                    clientStatusExpiresAt = clock.now() + 10.days,
                )
            val request =
                CredentialRequestTO(
                    credentialConfigurationId = PidMsoMdocV1CredentialConfigurationId.value,
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            val failed = assertIs<IssueCredentialResponse.FailedTO>(result)
            assertEquals(CredentialErrorTypeTo.CREDENTIAL_REQUEST_DENIED, failed.type)
        }

    @Test
    fun `fails with wrong scope`() =
        runTest {
            val authContext =
                authorizationContext(
                    scopes = nonEmptySetOf(Scope("wrong.scope")),
                )
            val request =
                CredentialRequestTO(
                    credentialConfigurationId = PidMsoMdocV1CredentialConfigurationId.value,
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            val failed = assertIs<IssueCredentialResponse.FailedTO>(result)
            assertEquals(CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, failed.type)
        }

    @Test
    fun `fails with multiple proof types`() =
        runTest {
            val authContext = authorizationContext()
            val request =
                CredentialRequestTO(
                    credentialConfigurationId = PidMsoMdocV1CredentialConfigurationId.value,
                    proofs =
                        CredentialRequestTO.ProofsTO(
                            jwtProofs = listOf(jwtProofString()),
                            attestations = listOf(jwtProofString()),
                        ),
                )

            val result = issueCredential.fromPlainRequest(authContext, request)

            val failed = assertIs<IssueCredentialResponse.FailedTO>(result)
            assertEquals(CredentialErrorTypeTo.INVALID_PROOF, failed.type)
        }
}
