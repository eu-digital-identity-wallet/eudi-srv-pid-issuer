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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.toNonEmptyListOrNull
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import com.nimbusds.oauth2.sdk.util.JSONUtils
import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPTokenAuthentication
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.loadResource
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateCNonce
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
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
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.Month
import java.util.*
import kotlin.String
import kotlin.collections.List
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
    protected lateinit var generateCNonce: GenerateCNonce

    @Autowired
    protected lateinit var credentialIssuerMetadata: CredentialIssuerMetaData

    protected final fun client(): WebTestClient =
        WebTestClient.bindToApplicationContext(applicationContext)
            .apply(springSecurity())
            .configureClient()
            .build()

    protected suspend fun jwtProof(
        audience: CredentialIssuerId,
        clock: Clock,
        nonce: String,
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
            .claim("nonce", nonce)
            .build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key))

        return jwt
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
                    birthPlace = PlaceOfBirth(
                        country = IsoCountry("GR"),
                        region = State("Attica"),
                        locality = City("Athens"),
                    ),
                    nationalities = nonEmptyListOf(Nationality("GR")),
                    ageOver18 = true,
                )
                val issuingCountry = IsoCountry("GR")
                val pidMetaData = PidMetaData(
                    issuanceDate = LocalDate.now(),
                    expiryDate = LocalDate.of(2030, 11, 10),
                    documentNumber = null,
                    issuingAuthority = IssuingAuthority.MemberState(issuingCountry),
                    personalAdministrativeNumber = null,
                    issuingCountry = issuingCountry,
                    issuingJurisdiction = null,
                )
                pid to pidMetaData
            }

        @Bean
        @Primary
        fun encodePidInCbor(): EncodePidInCbor = EncodePidInCbor { _, _, _, _, _ -> "PID" }
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
        "issuer.pid.mso_mdoc.key_attestations.required = true",
        "issuer.pid.mso_mdoc.key_attestations.constraints.key_storage = iso_18045_high, iso_18045_moderate",
        "issuer.pid.mso_mdoc.key_attestations.constraints.user_authentication = iso_18045_high, iso_18045_moderate",
    ],
)
internal class WalletApiEncryptionOptionalTest : BaseWalletApiTest() {

    /**
     * Verifies credential endpoint is not accessible by anonymous users.
     */
    @Test
    fun `requires authorization`() = runTest {
        client().post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId())
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isUnauthorized()
    }

    /**
     * Verifies that unknown credential formats cannot be deserialized.
     * The Application is expected to fail.
     */
    @Test
    fun `fails with unknown credential configuration id`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(
                requestByCredentialConfigurationId(credentialConfigurationId = "foo", proofs = ProofsTO(jwtProofs = listOf("proof"))),
            )
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        assertNotNull(response)
        assertEquals(CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, response.type)
        assertEquals("Unsupported Credential Configuration Id 'foo'", response.errorDescription)
    }

    /**
     * Verifies that proof of possession is required.
     * The Application is expected to fail.
     */
    @Test
    fun `fails when proof is not provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId())
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val error = assertIs<IssueCredentialResponse.FailedTO>(response)
        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, error.type)
        assertEquals("The Credential Request must include Proof of Possession", error.errorDescription)
    }

    /**
     * Verifies that when an incorrect scope is used, issuance fails.
     * The Application is expected to fail.
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
            .bodyValue(requestByCredentialConfigurationId(proofs = ProofsTO(jwtProofs = listOf("proof"))))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val error = assertIs<IssueCredentialResponse.FailedTO>(response)
        assertEquals(CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, error.type)
        assertEquals("Wrong scope. Expected ${PidMsoMdocScope.value}", error.errorDescription)
    }

    /**
     * Verifies that when both 'proof' and 'proofs' is provided in credential request, issuance fails.
     */
    @Test
    fun `fails when both proof and proofs is provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProof()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proof = proof, proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Only one of `proof` or `proofs` is allowed", response.errorDescription)
    }

    @Test
    fun `fails when multiple proof types are provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val proofs = ProofsTO(jwtProofs = listOf("jwt"), ldpVpProofs = listOf("ldp_vc"), attestations = listOf("attestation"))

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Only a single proof type is allowed", response.errorDescription)
    }

    @Test
    fun `fails when providing more proofs than allowed batch_size`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val keys = List(5) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = keys.map { key ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
                jwk(key.toPublicJWK())
            }
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("You can provide at most '3' proofs", response.errorDescription)
    }

    @Test
    fun `fails when proofs do not contain the same cnonce`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val keys = List(2) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = keys.map { key ->
            jwtProof(credentialIssuerMetadata.id, clock, generateCNonce(clock.instant(), Duration.ofMinutes(5L)), key) {
                jwk(key.toPublicJWK())
            }
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("CNonce is not valid", response.errorDescription)
    }

    /**
     * Verifies issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `issuance success by credential configuration id`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProof()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proof = proof))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(listOf(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID"))), issuedCredentials)
        assertNull(response.transactionId)
    }

    /**
     * Verifies batch issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `batch issuance success by credential configuration id`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val keys = List(2) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = keys.map { key ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
                jwk(key.toPublicJWK())
            }
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(keys.size, issuedCredentials.size)
        issuedCredentials.forEach {
            assertEquals(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")), it)
        }
        assertNull(response.transactionId)
    }

    /**
     * Verifies issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `issuance success by credential identifier`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProof()

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

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(listOf(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID"))), issuedCredentials)
        assertNull(response.transactionId)
    }

    @Test
    fun `fail when the sent key attestation does not match the expected attack protection requirements`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()

        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            keyStorageConstraints = listOf("iso_18045_enhanced-basic"),
            userAuthorizationConstraints = listOf("iso_18045_enhanced-basic"),
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val keyAttestationJwtProof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }

        val noKeyAttestationJwtProof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            jwk(jwtProofSigningKey.toPublicJWK())
        }

        val proofs = listOf(keyAttestationJwtProof, noKeyAttestationJwtProof).toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proof = null, proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof JWT", response.errorDescription)
    }

    @Test
    fun `when mixed jwt proofs with and without key attestations are sent,the distinct set of keys is used for issuance`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()

        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(jwtProofSigningKey) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val keyAttestationJwtProof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }

        val noKeyAttestationJwtProof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            jwk(jwtProofSigningKey.toPublicJWK())
        }

        val proofs = listOf(keyAttestationJwtProof, noKeyAttestationJwtProof).toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proof = null, proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(extraKeysNo + 1, issuedCredentials.size)
        assertNull(response.transactionId)
    }

    @Test
    fun `when duplicate keys exists in key attestation they are skipped`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 5
        val keyAttestationJwt = keyAttestationJWT(jwtProofSigningKey) {
            val key = ECKeyGenerator(Curve.P_256).generate()
            (0..<extraKeysNo).map { key }
        }

        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProof()

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

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(2, issuedCredentials.size)
        assertNull(response.transactionId)
    }

    @Test
    fun `issuance with key attestation in jwt proof is successful`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(jwtProofSigningKey) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProof()

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

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(extraKeysNo + 1, issuedCredentials.size)
        assertNull(response.transactionId)
    }

    @Test
    fun `issuance with attestation proof is successful`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val proof = keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            cNonce = previousCNonce,
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }.toAttestationProof()

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

        val issuedCredentials = assertNotNull(response.credentials)
        assertEquals(extraKeysNo + 1, issuedCredentials.size)
        assertNull(response.transactionId)
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

    private val jacksonObjectMapper: ObjectMapper by lazy { jacksonObjectMapper() }

    /**
     * Verifies issuance fails when encryption is not requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `issuance failure by credential configuration id when encryption is not requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProof()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proof = proof))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS, response.type)
        assertEquals("Invalid Credential Response Encryption Parameters", response.errorDescription)
    }

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `issuance success by credential configuration id when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }.toJwtProof()
        val encryptionKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proof = proof, credentialResponseEncryption = encryptionParameters))
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val claims = run {
            val jwt = EncryptedJWT.parse(response)
                .also {
                    it.decrypt(
                        DefaultJWEDecrypterFactory().createJWEDecrypter(
                            it.header,
                            encryptionKey.toECPrivateKey(),
                        ),
                    )
                }
            jwt.jwtClaimsSet
        }

        val issuedCredentials = assertNotNull(claims.getListClaim("credentials"))
        assertEquals(1, issuedCredentials.size)
        issuedCredentials.first().also {
            assertEquals(
                IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")),
                Json.decodeFromString<IssueCredentialResponse.PlainTO.CredentialTO>(jacksonObjectMapper.writeValueAsString(it)),
            )
        }
    }

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `batch issuance success by credential configuration id when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val walletKeys = List(2) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = walletKeys.map { walletKey ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
                jwk(walletKey.toPublicJWK())
            }
        }.toJwtProofs()
        val encryptionKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialConfigurationId(proofs = proofs, credentialResponseEncryption = encryptionParameters))
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val claims = run {
            val jwt = EncryptedJWT.parse(response)
                .also {
                    it.decrypt(
                        DefaultJWEDecrypterFactory().createJWEDecrypter(
                            it.header,
                            encryptionKey.toECPrivateKey(),
                        ),
                    )
                }
            jwt.jwtClaimsSet
        }
        val credentials = assertNotNull(claims.getListClaim("credentials"))
        assertEquals(walletKeys.size, credentials.size)
        credentials.forEach {
            assertEquals(
                IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")),
                Json.decodeFromString<IssueCredentialResponse.PlainTO.CredentialTO>(jacksonObjectMapper.writeValueAsString(it)),
            )
        }
    }

    /**
     * Verifies issuance fails when encryption is not requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `issuance failure by credential identifier when encryption is not requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProof()

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

        assertEquals(CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS, response.type)
        assertEquals("Invalid Credential Response Encryption Parameters", response.errorDescription)
    }

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `issuance success by credential identifier when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateCNonce(clock.instant(), Duration.ofMinutes(5L))

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }
        val encryptionKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(
                requestByCredentialIdentifier(
                    proof = proof.toJwtProof(),
                    credentialResponseEncryption = encryptionParameters,
                ),
            )
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val claims = run {
            val jwt = EncryptedJWT.parse(response)
                .also {
                    it.decrypt(
                        DefaultJWEDecrypterFactory().createJWEDecrypter(
                            it.header,
                            encryptionKey.toECPrivateKey(),
                        ),
                    )
                }
            jwt.jwtClaimsSet
        }

        val issuedCredentials = assertNotNull(claims.getListClaim("credentials"))
        assertEquals(1, issuedCredentials.size)
        issuedCredentials.first().also {
            assertEquals(
                IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")),
                Json.decodeFromString<IssueCredentialResponse.PlainTO.CredentialTO>(jacksonObjectMapper.writeValueAsString(it)),
            )
        }
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

private fun requestByCredentialConfigurationId(
    credentialConfigurationId: String = "eu.europa.ec.eudi.pid_mso_mdoc",
    proof: ProofTo? = null,
    proofs: ProofsTO? = null,
    credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
): CredentialRequestTO =
    CredentialRequestTO(
        credentialConfigurationId = credentialConfigurationId,
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

private fun encryptionParameters(key: ECKey): CredentialResponseEncryptionTO =
    CredentialResponseEncryptionTO(
        key = Json.decodeFromString(key.toPublicJWK().toJSONString()),
        algorithm = "ECDH-ES",
        method = "A128GCM",
    )

val KEY_ATTESTATION_JWT_TYPE = "keyattestation+jwt"

/**
 * Creates a key attestation jwt having as attested keys the one passed in [proofSigningKey]
 * plus a number of keys specified with [extraKeysNo].
 *
 * NOTE: The [proofSigningKey] is added last in the array of attested keys.
 *
 * @param proofSigningKey The key used to sign the JWT Proof
 * @param extraKeysNo   The extra keys to be generated and included in the 'attested_keys' array claim.
 */
private suspend fun keyAttestationJWT(
    proofSigningKey: ECKey,
    keyStorageConstraints: List<String> = listOf("iso_18045_high"),
    userAuthorizationConstraints: List<String> = listOf("iso_18045_high"),
    cNonce: String? = null,
    expiresAt: Instant = Instant.now().plus(Duration.ofDays(1)),
    extraKeys: () -> List<ECKey>,
): SignedJWT {
    val keyAttestationSigningKey = loadECKey("key-attestation-key.pem")
    val signer = ECDSASigner(keyAttestationSigningKey)

    val attestedKeys = extraKeys() + proofSigningKey

    val attestedKeysJsonArray = attestedKeys.map { key ->
        JSONUtils.parseJSON(key.toPublicJWK().toJSONString())
    }

    val chain = loadChain("key-attestation-chain.pem")
    val encodedChain = chain.map {
        com.nimbusds.jose.util.Base64.encode(it.encoded)
    }

    return SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(KEY_ATTESTATION_JWT_TYPE))
            .x509CertChain(encodedChain)
            .build(),
        JWTClaimsSet.Builder()
            .expirationTime(Date(expiresAt.toEpochMilli()))
            .issueTime(Date())
            .claim("attested_keys", attestedKeysJsonArray)
            .claim("key_storage", keyStorageConstraints)
            .claim("user_authentication", userAuthorizationConstraints)
            .claim("nonce", cNonce)
            .build(),
    ).apply { sign(signer) }
}

private suspend fun loadChain(filename: String): NonEmptyList<X509Certificate> =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/$filename")
            .readText()
            .let {
                X509CertChainUtils.parse(it)
            }
            .let {
                assertNotNull(it.toNonEmptyListOrNull())
            }
    }

private suspend fun loadECKey(filename: String): ECKey =
    withContext(Dispatchers.IO) {
        loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/jose/x5c/$filename")
            .readText()
            .let {
                ECKey.parseFromPEMEncodedObjects(it).toECKey()
            }
    }

private fun SignedJWT.toJwtProof(): ProofTo = ProofTo(type = ProofTypeTO.JWT, jwt = serialize())
private fun SignedJWT.toAttestationProof(): ProofTo = ProofTo(type = ProofTypeTO.ATTESTATION, attestation = serialize())
private fun SignedJWT.toJwtProofs(): ProofsTO = ProofsTO(jwtProofs = listOf(serialize()))
private fun Iterable<SignedJWT>.toJwtProofs(): ProofsTO = ProofsTO(jwtProofs = map { it.serialize() })
