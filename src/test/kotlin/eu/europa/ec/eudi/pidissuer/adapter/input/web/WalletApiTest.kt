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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.toNonEmptyListOrNull
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
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
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.loadResource
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateNonce
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.datetime.LocalDate
import kotlinx.datetime.Month
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
import java.util.*
import kotlin.test.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

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
    protected lateinit var generateNonce: GenerateNonce

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
            .issueTime(clock.now().toJavaDate())
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
                1L.minutes,
                10L.minutes,
                null,
            )

        @Bean
        @Primary
        fun getPidData(clock: Clock): GetPidData =
            GetPidData {
                val pid = Pid(
                    familyName = FamilyName("Surname"),
                    givenName = GivenName("Firstname"),
                    birthDate = LocalDate(1989, Month.AUGUST, 22),
                    placeOfBirth = PlaceOfBirth(
                        country = IsoCountry("GR"),
                        region = State("Attica"),
                        locality = City("Athens"),
                    ),
                    nationalities = nonEmptyListOf(Nationality("GR")),
                )
                val issuingCountry = IsoCountry("GR")
                val pidMetaData = PidMetaData(
                    issuanceDate = with(clock) { now().toLocalDate() },
                    expiryDate = LocalDate(2030, 11, 10),
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
        fun encodePidInCbor(): EncodePidInCbor = EncodePidInCbor { _, _, holderKey, _, _, _ ->
            println(holderKey)
            "PID"
        }
    }
}

/**
 * Test cases for [WalletApi] when encryption is optional. Key Attestations are **NOT** required.
 */
@TestPropertySource(
    properties = [
        "issuer.credentialRequestEncryption.required=false",
        "issuer.credentialResponseEncryption.required=false",
        "issuer.credentialEndpoint.batchIssuance.enabled=true",
        "issuer.credentialEndpoint.batchIssuance.batchSize=3",
        "issuer.pid.mso_mdoc.key_attestations.required=false",
    ],
)
internal class WalletApiEncryptionOptionalKeyAttestationsNotRequiredTest : BaseWalletApiTest() {

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
        assertEquals(CredentialErrorTypeTo.UNKNOWN_CREDENTIAL_CONFIGURATION, response.type)
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

    @Test
    fun `fails when multiple proof types are provided`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)

        val proofs = ProofsTO(jwtProofs = listOf("jwt"), diVpProofs = listOf("di_vc"), attestations = listOf("attestation"))

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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

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
            jwtProof(credentialIssuerMetadata.id, clock, generateNonce(clock.now(), 5L.minutes), key) {
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

        assertEquals(CredentialErrorTypeTo.INVALID_NONCE, response.type)
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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
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
    fun `fails when key_attestation is included when not required`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)
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

        val proofs = listOf(keyAttestationJwtProof).toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof JWT: JWT Proof cannot contain `key_attestation`", response.errorDescription)
    }

    @Test
    fun `issuance success by credential configuration id with encrypted request`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val credentialRequestEncryption = credentialIssuerMetadata.credentialRequestEncryption
        require(credentialRequestEncryption is CredentialRequestEncryption.Optional)

        val key = ECKeyGenerator(Curve.P_256)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("ec-key-0")
            .generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialConfigurationId(proofs = proofs)
                    .encrypt(credentialRequestEncryption.parameters),
            )
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val issuedCredentials = assertNotNull(response.credentials)
        issuedCredentials.forEach {
            assertEquals(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")), it)
        }
        assertNull(response.transactionId)
    }
}

/**
 * Test cases for [WalletApi] when encryption is optional. Key Attestations are **REQUIRED**.
 */
@TestPropertySource(
    properties = [
        "issuer.credentialRequestEncryption.required=false",
        "issuer.credentialResponseEncryption.required=false",
        "issuer.credentialEndpoint.batchIssuance.enabled=true",
        "issuer.credentialEndpoint.batchIssuance.batchSize=3",
        "issuer.pid.mso_mdoc.key_attestations.required=true",
        "issuer.pid.mso_mdoc.key_attestations.constraints.key_storage=iso_18045_high,iso_18045_moderate",
        "issuer.pid.mso_mdoc.key_attestations.constraints.user_authentication=iso_18045_high,iso_18045_moderate",
    ],
)
internal class WalletApiEncryptionOptionalKeyAttestationsRequiredTest : BaseWalletApiTest() {

    @Test
    fun `fail when the sent key attestation does not match the expected attack protection requirements`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)
        val keyAttestationCNonce = generateNonce(clock.now(), 5L.minutes)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()

        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            keyStorageConstraints = listOf("iso_18045_enhanced-basic"),
            userAuthorizationConstraints = listOf("iso_18045_enhanced-basic"),
            cNonce = keyAttestationCNonce,
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val keyAttestationJwtProof = jwtProof(credentialIssuerMetadata.id, clock, keyAttestationCNonce, jwtProofSigningKey) {
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
            .bodyValue(requestByCredentialIdentifier(proofs = proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals(
            "Invalid proof JWT: The provided key storage's attack resistance does not match the expected one.",
            response.errorDescription,
        )
    }

    @Test
    fun `when duplicate keys exists in key attestation they are skipped`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val cNonce = generateNonce(clock.now(), 5L.minutes)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 5
        val keyAttestationJwt = keyAttestationJWT(proofSigningKey = jwtProofSigningKey, cNonce = cNonce) {
            val key = ECKeyGenerator(Curve.P_256).generate()
            (0..<extraKeysNo).map { key }
        }

        val proofs = jwtProof(credentialIssuerMetadata.id, clock, cNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
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
    fun `when key attestation in jwt proof, it must contain valid 'exp' claim, otherwise issuance fails `() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)
        val keyAttestationCNonce = generateNonce(clock.now(), 5L.minutes)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3

        // /////////////////////////////////
        // key attestation missing 'exp' //
        // /////////////////////////////////

        var keyAttestationJwt = keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            cNonce = keyAttestationCNonce,
            includeExpiresAt = false,
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        var proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        var response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof JWT: JWT missing required claims: [exp]", response.errorDescription)

        // ///////////////////////////
        // key attestation expired //
        // ///////////////////////////

        keyAttestationJwt = keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            cNonce = keyAttestationCNonce,
            expiresAt = clock.now().minus(3L.minutes),
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }
        proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof JWT: Expired JWT", response.errorDescription)
    }

    @Test
    fun `issuance with jwt proof that contains key attestation with nonce is successful`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val cNonce = generateNonce(clock.now(), 5L.minutes)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(proofSigningKey = jwtProofSigningKey, cNonce = cNonce) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val proofs = jwtProof(credentialIssuerMetadata.id, clock, cNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
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
    fun `issuance with jwt proof that contains key attestation without nonce is successful`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val cNonce = generateNonce(clock.now(), 5L.minutes)
        val keyAttestationJwt = keyAttestationJWT(proofSigningKey = jwtProofSigningKey) {
            (0..<3).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, cNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val issuedCredentials = assertNotNull(response.credentials)
        issuedCredentials.forEach {
            assertEquals(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")), it)
        }
        assertNull(response.transactionId)
    }

    @Test
    fun `issuance with jwt proof that contains key attestation with difference nonce fails`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val keyAttestationCNonce = generateNonce(clock.now(), 5L.minutes)
        val keyAttestationJwt = keyAttestationJWT(proofSigningKey = jwtProofSigningKey, cNonce = keyAttestationCNonce) {
            (0..<3).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val jwtProofCNonce = generateNonce(clock.now(), 5L.minutes)
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, jwtProofCNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof JWT: Key Attestation 'nonce' does not match JWT Proof 'nonce'", response.errorDescription)
    }

    @Test
    internal fun `issuance with jwt proof that contains key attestation fails when proof is signed with non-attested key`() =
        runTest {
            val authentication = dPoPTokenAuthentication(clock = clock)
            val cNonce = generateNonce(clock.now(), 5L.minutes)
            val nonAttestedProofKey = ECKeyGenerator(Curve.P_256).generate()
            val attestedKey = ECKeyGenerator(Curve.P_256).generate()
            val keyAttestationJwt = keyAttestationJWT(proofSigningKey = attestedKey)

            val proofs = jwtProof(credentialIssuerMetadata.id, clock, cNonce, nonAttestedProofKey) {
                customParam("key_attestation", keyAttestationJwt.serialize())
            }.toJwtProofs()

            val response = client()
                .mutateWith(mockAuthentication(authentication))
                .post()
                .uri(WalletApi.CREDENTIAL_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestByCredentialIdentifier(proofs))
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody<IssueCredentialResponse.FailedTO>()
                .returnResult()
                .let { assertNotNull(it.responseBody) }

            assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
            assertEquals(
                "Invalid proof JWT: Key attestation does not contain a key that verifies the jwt proof signature",
                response.errorDescription,
            )
        }

    @Test
    fun `issuance with attestation proof (without 'exp' claim) is successful`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val keyAttestationCNonce = generateNonce(clock.now(), 5L.minutes)
        val signingKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val proofs = keyAttestationJWT(
            proofSigningKey = signingKey,
            cNonce = keyAttestationCNonce,
            includeExpiresAt = false,
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }.toAttestationProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
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
    fun `issuance with expired attestation proof fails`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val keyAttestationCNonce = generateNonce(clock.now(), 5L.minutes)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val proofs = keyAttestationJWT(
            proofSigningKey = jwtProofSigningKey,
            cNonce = keyAttestationCNonce,
            expiresAt = clock.now().minus(3L.minutes),
        ) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }.toAttestationProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof Attestation: Expired JWT", response.errorDescription)
    }

    @Test
    fun `when key attestations does not contain cNonce, issuance fails`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(proofSigningKey = jwtProofSigningKey) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(keyAttestationJwt.toAttestationProofs()))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_PROOF, response.type)
        assertEquals("Invalid proof Attestation: Key attestation does not contain a c_nonce.", response.errorDescription)
    }

    @Test
    fun `issuance success by credential configuration id with encrypted request`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val cNonce = generateNonce(clock.now(), 5L.minutes)

        val credentialRequestEncryption = credentialIssuerMetadata.credentialRequestEncryption
        require(credentialRequestEncryption is CredentialRequestEncryption.Optional)

        val jwtProofSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val extraKeysNo = 3
        val keyAttestationJwt = keyAttestationJWT(proofSigningKey = jwtProofSigningKey, cNonce = cNonce) {
            (0..<extraKeysNo).map {
                ECKeyGenerator(Curve.P_256).generate()
            }
        }

        val proofs = jwtProof(credentialIssuerMetadata.id, clock, cNonce, jwtProofSigningKey) {
            customParam("key_attestation", keyAttestationJwt.serialize())
        }.toJwtProofs()

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialConfigurationId(proofs = proofs)
                    .encrypt(credentialRequestEncryption.parameters),
            )
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val issuedCredentials = assertNotNull(response.credentials)
        issuedCredentials.forEach {
            assertEquals(IssueCredentialResponse.PlainTO.CredentialTO(JsonPrimitive("PID")), it)
        }
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
internal class WalletApiResponseEncryptionRequiredTest : BaseWalletApiTest() {

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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProofs()

        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialConfigurationId(proofs = proofs)
                    .encrypt(credentialRequestEncryption.parameters),
            )
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS, response.type)
        assertEquals(
            "Invalid Credential Response Encryption Parameters: credential response encryption is required",
            response.errorDescription,
        )
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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }.toJwtProofs()
        val encryptionKey = ECKeyGenerator(Curve.P_256).algorithm(JWEAlgorithm.ECDH_ES).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionResponseParameters(encryptionKey)

        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialConfigurationId(proofs = proofs, credentialResponseEncryption = encryptionParameters)
                    .encrypt(credentialRequestEncryption.parameters),
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

    /**
     * Verifies issuance succeeds when encryption is requested.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies response values.
     */
    @Test
    fun `batch issuance success by credential configuration id when encryption is requested`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val walletKeys = List(2) { ECKeyGenerator(Curve.P_256).generate() }
        val proofs = walletKeys.map { walletKey ->
            jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
                jwk(walletKey.toPublicJWK())
            }
        }.toJwtProofs()
        val encryptionKey = ECKeyGenerator(Curve.P_256).algorithm(JWEAlgorithm.ECDH_ES).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionResponseParameters(encryptionKey)

        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialConfigurationId(proofs = proofs, credentialResponseEncryption = encryptionParameters)
                    .encrypt(credentialRequestEncryption.parameters),
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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProofs()

        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialIdentifier(proofs)
                    .encrypt(credentialRequestEncryption.parameters),
            )
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_ENCRYPTION_PARAMETERS, response.type)
        assertEquals(
            "Invalid Credential Response Encryption Parameters: credential response encryption is required",
            response.errorDescription,
        )
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
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }
        val encryptionKey = ECKeyGenerator(Curve.P_256).algorithm(JWEAlgorithm.ECDH_ES).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionResponseParameters(encryptionKey)

        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestByCredentialIdentifier(
                    proofs = proof.toJwtProofs(),
                    credentialResponseEncryption = encryptionParameters,
                ).encrypt(credentialRequestEncryption.parameters),
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

    @Test
    fun `issuance fails when credential response is encrypted but credential request is not encrypted`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val key = ECKeyGenerator(Curve.P_256).generate()
        val proofs = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, key) {
            jwk(key.toPublicJWK())
        }.toJwtProofs()
        val encryptionKey = ECKeyGenerator(Curve.P_256).algorithm(JWEAlgorithm.ECDH_ES).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionResponseParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestByCredentialIdentifier(proofs, encryptionParameters))
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        assertEquals(CredentialErrorTypeTo.INVALID_CREDENTIAL_REQUEST, response.type)
        assertEquals("Credential response encryption requires an encrypted credential request", response.errorDescription)
    }
}

@TestPropertySource(
    properties = [
        "issuer.credentialRequestEncryption.required=false",
        "issuer.credentialResponseEncryption.required=false",
    ],
)
internal class WalletApiDeferredIssuanceResponseEncryptionOptionalTest : BaseWalletApiTest() {

    @Test fun `deferred issuance succeeds when credential request is plain`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(
                requestDeferredByCredentialIdentifier(
                    proofs = proof.toJwtProofs(),
                ),
            )
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isAccepted()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val transactionId = assertNotNull(response.transactionId)
        val interval = assertNotNull(response.interval)

        val getDeferredCredentialResponse = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.DEFERRED_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(DeferredCredentialRequestTO(transactionId))
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isAccepted()
            .expectBody<IssuancePendingTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val defTransactionId = assertNotNull(getDeferredCredentialResponse.transactionId)
        val defInterval = assertNotNull(getDeferredCredentialResponse.interval)
        assertEquals(transactionId, defTransactionId)
    }
}

@TestPropertySource(
    properties = [
        "issuer.credentialResponseEncryption.required=true",
        "issuer.pid.sd_jwt_vc.enabled=true",
    ],
)
internal class WalletApiDeferredIssuanceResponseEncryptionRequiredTest : BaseWalletApiTest() {

    @Test fun `deferred issuance succeeds when credential request is encrypted`() = runTest {
        val authentication = dPoPTokenAuthentication(clock = clock)
        val previousCNonce = generateNonce(clock.now(), 5L.minutes)

        val walletKey = ECKeyGenerator(Curve.P_256).generate()
        val proof = jwtProof(credentialIssuerMetadata.id, clock, previousCNonce, walletKey) {
            jwk(walletKey.toPublicJWK())
        }
        val encryptionKey = ECKeyGenerator(Curve.P_256).algorithm(JWEAlgorithm.ECDH_ES).keyUse(KeyUse.ENCRYPTION).generate()
        val encryptionParameters = encryptionResponseParameters(encryptionKey)

        val response = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                requestDeferredByCredentialIdentifier(
                    proofs = proof.toJwtProofs(),
                    credentialResponseEncryption = encryptionParameters,
                ).encrypt((credentialIssuerMetadata.credentialRequestEncryption as CredentialRequestEncryption.Required).parameters),
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

        val transactionId = assertNotNull(claims.getStringClaim("transaction_id"))
        val interval = assertNotNull(claims.getLongClaim("interval"))

        val getDeferredCredentialResponse = client()
            .mutateWith(mockAuthentication(authentication))
            .post()
            .uri(WalletApi.DEFERRED_ENDPOINT)
            .contentType(MediaType.parseMediaType("application/jwt"))
            .bodyValue(
                DeferredCredentialRequestTO(transactionId, encryptionParameters)
                    .encrypt((credentialIssuerMetadata.credentialRequestEncryption as CredentialRequestEncryption.Required).parameters),
            )
            .accept(MediaType.parseMediaType("application/jwt"))
            .exchange()
            .expectStatus().isAccepted()
            .expectBody<String>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val defClaims = run {
            val jwt = EncryptedJWT.parse(getDeferredCredentialResponse)
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

        val defTransactionId = assertNotNull(defClaims.getStringClaim("transaction_id"))
        assertEquals(transactionId, defTransactionId)
    }
}

private fun dPoPTokenAuthentication(
    subject: String = "user",
    clock: Clock,
    expiresIn: Duration = 10L.minutes,
    scopes: List<Scope> = listOf(PidMsoMdocScope, PidSdJwtVcScope),
    authorities: List<GrantedAuthority> = listOf(SimpleGrantedAuthority("ROLE_USER")),
): DPoPTokenAuthentication {
    val issuedAt = clock.now()
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
    proofs: ProofsTO? = null,
    credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
): CredentialRequestTO =
    CredentialRequestTO(
        credentialConfigurationId = credentialConfigurationId,
        proofs = proofs,
        credentialResponseEncryption = credentialResponseEncryption,
    )

private fun requestByCredentialIdentifier(
    proofs: ProofsTO? = null,
    credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
): CredentialRequestTO =
    CredentialRequestTO(
        credentialIdentifier = "eu.europa.ec.eudi.pid_mso_mdoc",
        proofs = proofs,
        credentialResponseEncryption = credentialResponseEncryption,
    )

private fun requestDeferredByCredentialIdentifier(
    proofs: ProofsTO? = null,
    credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
): CredentialRequestTO =
    CredentialRequestTO(
        credentialConfigurationId = "eu.europa.ec.eudi.pid_vc_sd_jwt_deferred",
        proofs = proofs,
        credentialResponseEncryption = credentialResponseEncryption,
    )

private fun encryptionResponseParameters(key: ECKey): CredentialResponseEncryptionTO =
    CredentialResponseEncryptionTO(
        key = Json.decodeFromString(key.toPublicJWK().toJSONString()),
        method = "A128GCM",
        zipAlgorithm = "DEF",
    )

private fun encryptPayload(payload: String, encParams: CredentialRequestEncryptionSupportedParameters): String =
    JWEObject(
        JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encParams.methodsSupported.head)
            .keyID(encParams.encryptionKeys.keys[0].keyID)
            .jwk(encParams.encryptionKeys.keys[0].toPublicJWK())
            .type(JOSEObjectType.JWT)
            .build(),
        Payload(payload),
    ).apply {
        encrypt(
            ECDHEncrypter(encParams.encryptionKeys.keys[0].toECKey()),
        )
    }.serialize()

private fun CredentialRequestTO.encrypt(encParams: CredentialRequestEncryptionSupportedParameters): String =
    encryptPayload(Json.encodeToString(this), encParams)

private fun DeferredCredentialRequestTO.encrypt(encParams: CredentialRequestEncryptionSupportedParameters): String =
    encryptPayload(Json.encodeToString(this), encParams)

/**
 * Creates a key attestation jwt having as attested keys the one passed in [proofSigningKey]
 * plus a number of keys generated from [extraKeys] function.
 *
 * NOTE: The [proofSigningKey] is added last in the array of attested keys.
 *
 * @param proofSigningKey The key used to sign the JWT Proof
 * @param extraKeys   Function that generates the extra keys to be included in the 'attested_keys' array claim.
 */
private suspend fun keyAttestationJWT(
    proofSigningKey: ECKey,
    keyStorageConstraints: List<String> = listOf("iso_18045_high"),
    userAuthorizationConstraints: List<String> = listOf("iso_18045_high"),
    cNonce: String? = null,
    clock: Clock = Clock.System,
    expiresAt: Instant = clock.now() + 1.days,
    includeExpiresAt: Boolean = true,
    extraKeys: () -> List<ECKey> = { emptyList() },
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

    val builder = JWTClaimsSet.Builder()
    if (includeExpiresAt) {
        builder.expirationTime(expiresAt.toJavaDate())
    }
    val claimsSet = builder
        .issueTime(Date())
        .claim("attested_keys", attestedKeysJsonArray)
        .claim("key_storage", keyStorageConstraints)
        .claim("user_authentication", userAuthorizationConstraints)
        .claim("nonce", cNonce)
        .build()

    return SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE))
            .x509CertChain(encodedChain)
            .build(),
        claimsSet,
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

private fun SignedJWT.toAttestationProofs(): ProofsTO = ProofsTO(attestations = listOf(serialize()))
private fun SignedJWT.toJwtProofs(): ProofsTO = ProofsTO(jwtProofs = listOf(serialize()))
private fun Iterable<SignedJWT>.toJwtProofs(): ProofsTO = ProofsTO(jwtProofs = map { it.serialize() })
