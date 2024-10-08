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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPTokenAuthentication
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateCNonce
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import java.net.URI
import java.time.Clock
import java.time.Duration
import java.time.LocalDate
import java.time.Month
import java.util.*
import kotlin.test.*

/**
 * Base class for [WalletApi] tests.
 */
@PidIssuerApplicationTest(classes = [BaseWalletApiTest.WalletApiTestConfig::class])
internal class BaseWalletApiTest {

    @Autowired
    protected lateinit var applicationContext: ApplicationContext

    @Autowired
    protected lateinit var clock: Clock

    @Autowired
    protected lateinit var cNonceRepository: InMemoryCNonceRepository

    @Autowired
    protected lateinit var generateCNonce: GenerateCNonce

    @Autowired
    protected lateinit var credentialIssuerMetadata: CredentialIssuerMetaData

    protected final fun client(): WebTestClient =
        WebTestClient.bindToApplicationContext(applicationContext)
            .apply(springSecurity())
            .configureClient()
            .build()

    @BeforeTest
    internal fun setup() = runBlocking {
        cNonceRepository.clear()
    }

    @TestConfiguration
    class WalletApiTestConfig {

        @Bean
        @Primary
        fun dPoPConfigurationProperties(): DPoPConfigurationProperties =
            DPoPConfigurationProperties(
                emptySet(),
                Duration.ofMinutes(1L),
                Duration.ofMinutes(10L),
                null,
            )

        @Bean
        @Primary
        fun getPidData(): GetPidData =
            GetPidData {
                val pid = Pid(
                    familyName = FamilyName("Surname"),
                    givenName = GivenName("Firstname"),
                    birthDate = LocalDate.of(1989, Month.AUGUST, 22),
                    ageOver18 = true,
                )
                val issuingCountry = IsoCountry("GR")
                val pidMetaData = PidMetaData(
                    issuanceDate = LocalDate.now(),
                    expiryDate = LocalDate.of(2030, 11, 10),
                    documentNumber = null,
                    issuingAuthority = IssuingAuthority.MemberState(issuingCountry),
                    administrativeNumber = null,
                    issuingCountry = issuingCountry,
                    issuingJurisdiction = null,
                )
                pid to pidMetaData
            }

        @Bean
        @Primary
        fun encodePidInCbor(): EncodePidInCbor = EncodePidInCbor { _, _, _ -> "PID" }
    }
}

/**
 * Test cases for [WalletApi] when encryption is optional.
 */
@TestPropertySource(
    properties = [
        "issuer.credentialResponseEncryption.required=false",
        "issuer.credentialEndpoint.batchIssuance.enabled=true",
        "issuer.credentialEndpoint.batchIssuance.batchSize=3",
    ],
)
internal class WalletApiEncryptionOptionalTest : BaseWalletApiTest() {

    /**
     * Verifies credential endpoint is not accessible by anonymous users.
     * No CNonce is expected to be generated.
     */
    @Test
    fun `requires authorization`() = runTest {
        client().post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat())
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isUnauthorized()
    }

    /**
     * Verifies that unknown credential formats cannot be deserialized.
     * The Application is expected to fail.
     * No CNonce is expected to be generated.
     */
    @Test
    fun `fails with unknown credential request format`() = runTest {
        val request = """
            {
              "format": "pid"
            }
        """.trimIndent()

        val authentication = dPoPTokenAuthentication(clock = clock)

        client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectAll(
                { it.expectStatus().is5xxServerError() },
                {
                    it.expectBody()
                        .jsonPath("$.trace")
                        .value<String> {
                            assertTrue { "FormatTO does not contain element with name 'pid'" in it }
                        }
                },
            )
    }

    /**
     * Verifies that proof of possession is required.
     * The Application is expected to fail.
     * CNonce is expected to be generated.
     */
    @Test
    fun `fails when proof is not provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(null))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val cNonce =
            assertNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))

        assertEquals(
            IssueCredentialResponse.FailedTO(
                CredentialErrorTypeTo.INVALID_PROOF,
                "The Credential Request must include Proof of Possession",
                cNonce.nonce,
                cNonce.expiresIn.toSeconds(),
            ),
            response,
        )
    }

    /**
     * Verifies that when an incorrect scope is used, issuance fails.
     * The Application is expected to fail.
     * CNonce is expected to be generated.
     */
    @Test
    fun `fails when using incorrect scope`() = runTest {
        val authentication = dPoPTokenAuthentication(
            clock = clock,
            scopes = listOf(PidSdJwtVcScope),
        )

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proofs = ProofsTO(jwtProofs = listOf("proof"))))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val cNonce =
            assertNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))

        assertEquals(
            IssueCredentialResponse.FailedTO(
                CredentialErrorTypeTo.INVALID_REQUEST,
                "Wrong scope. Expecting $PidMsoMdocScope",
                cNonce.nonce,
                cNonce.expiresIn.toSeconds(),
            ),
            response,
        )
    }

    /**
     * Verifies that when a CNonce is not active for the provided Access Token, issuance fails.
     * Application is expected to fail.
     * CNonce is expected to be generated.
     */
    @Test
    fun `fails when using no c_nonce is active`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat())
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val cNonce =
            assertNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))

        assertEquals(
            IssueCredentialResponse.FailedTO(
                CredentialErrorTypeTo.INVALID_PROOF,
                "The Credential Request must include Proof of Possession",
                cNonce.nonce,
                cNonce.expiresIn.toSeconds(),
            ),
            response,
        )
    }

    /**
     * Verifies that when both 'proof' and 'proofs' is provided in credential request, issuance fails.
     */
    @Test
    fun `fails when both proof and proofs is provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toProof()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proof = proof, proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        assertEquals(
            IssueCredentialResponse.FailedTO(
                CredentialErrorTypeTo.INVALID_PROOF,
                "Only one of `proof` or `proofs` is allowed",
                newCNonce.nonce,
                newCNonce.expiresIn.toSeconds(),
            ),
            response,
        )
    }

    @Test
    fun `fails when multiple proof types are provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val proofs = ProofsTO(jwtProofs = listOf("jwt"), ldpVpProofs = listOf("ldp_vc"))

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        assertEquals(
            IssueCredentialResponse.FailedTO(
                CredentialErrorTypeTo.INVALID_PROOF,
                "Only a single proof type is allowed",
                newCNonce.nonce,
                newCNonce.expiresIn.toSeconds(),
            ),
            response,
        )
    }

    @Test
    fun `fails when providing more proofs than allowed batch_size`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val keys = List(5) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = keys.map { key ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
                jwk(key.toPublicJWK())
            }
        }.toProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        assertEquals(
            IssueCredentialResponse.FailedTO(
                CredentialErrorTypeTo.INVALID_PROOF,
                "You can provide at most '3' proofs",
                newCNonce.nonce,
                newCNonce.expiresIn.toSeconds(),
            ),
            response,
        )
    }

    /**
     * Verifies issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `issuance success by format`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toProof()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proof))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        val issuedCredential = assertIs<JsonPrimitive>(response.credential)
        assertEquals("PID", issuedCredential.contentOrNull)
        assertNull(response.transactionId)
        assertEquals(newCNonce.nonce, response.nonce)
        assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
    }

    /**
     * Verifies batch issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `batch issuance success by format`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val keys = List(2) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = keys.map { key ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
                jwk(key.toPublicJWK())
            }
        }.toProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        assertNull(response.credential)
        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(keys.size, issuedCredentials.size)
        issuedCredentials.forEach {
            val issuedCredential = assertIs<JsonPrimitive>(it)
            assertEquals("PID", issuedCredential.contentOrNull)
        }
        assertNull(response.transactionId)
        assertEquals(newCNonce.nonce, response.nonce)
        assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
    }

    /**
     * Verifies issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `issuance success by credential identifier`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toProof()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proof))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        val issuedCredential = assertIs<JsonPrimitive>(response.credential)
        assertEquals("PID", issuedCredential.contentOrNull)
        assertNull(response.transactionId)
        assertEquals(newCNonce.nonce, response.nonce)
        assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
    }
}

/**
 * Test cases for [WalletApi] when encryption is required.
 */
@TestPropertySource(
    properties = [
        "issuer.credentialResponseEncryption.required=true",
        "issuer.credentialEndpoint.batchIssuance.enabled=true",
        "issuer.credentialEndpoint.batchIssuance.batchSize=3",
    ],
)
internal class WalletApiEncryptionRequiredTest : BaseWalletApiTest() {

    /**
     * Verifies issuance fails when encryption is not requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `issuance failure by format when encryption is not requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toProof()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proof))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)
        assertEquals(CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS, response.type)
        assertEquals("Invalid Credential Response Encryption Parameters", response.errorDescription)
        assertEquals(newCNonce.nonce, response.nonce)
        assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
    }

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `issuance success by format when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }.toProof()
        val encryptionKey = RSAKeyGenerator(4096).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proof = proof, credentialResponseEncryption = encryptionParameters))
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        val claims = run {
            val jwt = EncryptedJWT.parse(response)
                .also {
                    it.decrypt(
                        DefaultJWEDecrypterFactory().createJWEDecrypter(
                            it.header,
                            encryptionKey.toRSAPrivateKey(),
                        ),
                    )
                }
            jwt.jwtClaimsSet
        }
        assertEquals("PID", claims.getStringClaim("credential"))
        assertEquals(newCNonce.nonce, claims.getStringClaim("c_nonce"))
        assertEquals(newCNonce.expiresIn.seconds, claims.getLongClaim("c_nonce_expires_in"))
    }

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `batch issuance success by format when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val walletKeys = List(2) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = walletKeys.map { walletKey ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
                jwk(walletKey.toPublicJWK())
            }
        }.toProofs()
        val encryptionKey = RSAKeyGenerator(4096).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByFormat(proofs = proofs, credentialResponseEncryption = encryptionParameters))
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        val claims = run {
            val jwt = EncryptedJWT.parse(response)
                .also {
                    it.decrypt(
                        DefaultJWEDecrypterFactory().createJWEDecrypter(
                            it.header,
                            encryptionKey.toRSAPrivateKey(),
                        ),
                    )
                }
            jwt.jwtClaimsSet
        }
        assertNull(claims.getStringClaim("credential"))
        val credentials = assertNotNull(claims.getListClaim("credentials"))
        assertEquals(walletKeys.size, credentials.size)
        credentials.forEach {
            assertEquals("PID", it)
        }
        assertEquals(newCNonce.nonce, claims.getStringClaim("c_nonce"))
        assertEquals(newCNonce.expiresIn.seconds, claims.getLongClaim("c_nonce_expires_in"))
    }

    /**
     * Verifies issuance fails when encryption is not requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `issuance failure by credential identifier when encryption is not requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toProof()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proof))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)
        assertEquals(CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS, response.type)
        assertEquals("Invalid Credential Response Encryption Parameters", response.errorDescription)
        assertEquals(newCNonce.nonce, response.nonce)
        assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
    }

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    fun `issuance success by credential identifier when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(authentication.accessToken.toAuthorizationHeader(), clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }
        val encryptionKey = RSAKeyGenerator(4096).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(
                requestByCredentialIdentifier(
                    proof = proof.toProof(),
                    credentialResponseEncryption = encryptionParameters,
                ),
            )
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce =
            checkNotNull(cNonceRepository.loadCNonceByAccessToken(authentication.accessToken.toAuthorizationHeader()))
        assertNotEquals(previousCNonce, newCNonce)

        val claims = run {
            val jwt = EncryptedJWT.parse(response)
                .also {
                    it.decrypt(
                        DefaultJWEDecrypterFactory().createJWEDecrypter(
                            it.header,
                            encryptionKey.toRSAPrivateKey(),
                        ),
                    )
                }
            jwt.jwtClaimsSet
        }
        assertEquals("PID", claims.getStringClaim("credential"))
        assertEquals(newCNonce.nonce, claims.getStringClaim("c_nonce"))
        assertEquals(newCNonce.expiresIn.seconds, claims.getLongClaim("c_nonce_expires_in"))
    }
}

private fun dPoPTokenAuthentication(
    subject: String = "user",
    clock: Clock,
    expiresIn: Duration = Duration.ofMinutes(10L),
    scopes: List<Scope> = listOf(PidMsoMdocScope, PidSdJwtVcScope),
    authorities: List<GrantedAuthority> = listOf(SimpleGrantedAuthority("ROLE_USER")),
): DPoPTokenAuthentication {
    val issuedAt = clock.instant()
    val principal = DefaultOAuth2AuthenticatedPrincipal(
        subject,
        mapOf(
            OAuth2TokenIntrospectionClaimNames.ACTIVE to true,
            OAuth2TokenIntrospectionClaimNames.USERNAME to subject,
            OAuth2TokenIntrospectionClaimNames.CLIENT_ID to "wallet-dev",
            OAuth2TokenIntrospectionClaimNames.SCOPE to scopes.map { it.value },
            OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE to TokenType.BEARER.value,
            OAuth2TokenIntrospectionClaimNames.EXP to (issuedAt + expiresIn),
            OAuth2TokenIntrospectionClaimNames.IAT to issuedAt,
            OAuth2TokenIntrospectionClaimNames.NBF to issuedAt,
            OAuth2TokenIntrospectionClaimNames.SUB to subject,
            OAuth2TokenIntrospectionClaimNames.JTI to UUID.randomUUID().toString(),
        ),
        authorities + scopes.map { SimpleGrantedAuthority("SCOPE_${it.value}") },
    )
    val accessToken = DPoPAccessToken("token")

    return DPoPTokenAuthentication.unauthenticated(
        SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).build(), JWTClaimsSet.Builder().build()),
        accessToken,
        HttpMethod.GET,
        URI.create("/"),
    ).authenticate(principal)
}

private fun requestByFormat(
    proof: ProofTo? = null,
    proofs: ProofsTO? = null,
    credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
): CredentialRequestTO =
    CredentialRequestTO(
        format = FormatTO.MsoMdoc,
        docType = "eu.europa.ec.eudi.pid.1",
        proof = proof,
        proofs = proofs,
        credentialResponseEncryption = credentialResponseEncryption,
    )

private fun requestByCredentialIdentifier(
    proof: ProofTo? = ProofTo(type = ProofTypeTO.JWT, jwt = "123456"),
    proofs: ProofsTO? = null,
    credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
): CredentialRequestTO =
    CredentialRequestTO(
        credentialIdentifier = "eu.europa.ec.eudi.pid_mso_mdoc",
        proof = proof,
        proofs = proofs,
        credentialResponseEncryption = credentialResponseEncryption,
    )

private fun encryptionParameters(key: RSAKey): CredentialResponseEncryptionTO =
    CredentialResponseEncryptionTO(
        key = Json.decodeFromString(key.toPublicJWK().toJSONString()),
        algorithm = "RSA-OAEP-256",
        method = "A128CBC-HS256",
    )

private fun jwtProof(
    audience: CredentialIssuerId,
    clock: Clock,
    nonce: CNonce,
    key: ECKey,
    headerCustomizer: JWSHeader.Builder.() -> Unit = { },
): SignedJWT {
    val header = JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(JOSEObjectType("openid4vci-proof+jwt"))
        .apply(headerCustomizer)
        .build()
    val claims = JWTClaimsSet.Builder()
        .audience(audience.externalForm)
        .issueTime(Date.from(clock.instant()))
        .claim("nonce", nonce.nonce)
        .build()
    val jwt = SignedJWT(header, claims)
    jwt.sign(ECDSASigner(key))

    return jwt
}

private fun SignedJWT.toProof(): ProofTo = ProofTo(type = ProofTypeTO.JWT, jwt = serialize())
private fun SignedJWT.toProofs(): ProofsTO = ProofsTO(jwtProofs = listOf(serialize()))
private fun Iterable<SignedJWT>.toProofs(): ProofsTO = ProofsTO(jwtProofs = map { it.serialize() })
