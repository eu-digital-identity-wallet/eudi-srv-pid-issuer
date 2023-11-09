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

import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateJwtProof
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.domain.CredentialKey
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.CredentialErrorTypeTo
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenCNonce
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOpaqueToken
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import java.time.Clock
import java.time.Duration
import java.time.LocalDate
import java.time.Month
import java.util.*
import kotlin.test.*

@PidIssuerApplicationTest(classes = [WalletApiTestConfig::class])
@OptIn(ExperimentalCoroutinesApi::class)
@TestPropertySource(properties = ["issuer.credentialResponseEncryption.required=false"])
internal class WalletApiTest {

    @Autowired
    private lateinit var applicationContext: ApplicationContext

    @Autowired
    private lateinit var clock: Clock

    @Autowired
    private lateinit var cNonceRepository: InMemoryCNonceRepository

    @Autowired
    private lateinit var genCNonce: GenCNonce

    private fun client(): WebTestClient =
        WebTestClient.bindToApplicationContext(applicationContext)
            .apply(springSecurity())
            .configureClient()
            .build()

    @BeforeTest
    internal fun setup() = runBlocking {
        cNonceRepository.clear()
    }

    /**
     * Verifies credential endpoint is not accessible by anonymous users.
     * No CNonce is expected to be generated.
     */
    @Test
    fun `requires authorization`() = runTest {
        client().post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
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

        val (principal, _) = bearerTokenAuthenticationPrincipal(clock = clock)

        client()
            .mutateWith(mockOpaqueToken().principal(principal))
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
                        .value<String> { value ->
                            value.contains("Polymorphic serializer was not found for class discriminator")
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
        val request = """
            {
              "format": "mso_mdoc",
              "doctype": "eu.europa.ec.eudiw.pid.1"
            }
        """.trimIndent()

        val (principal, token) = bearerTokenAuthenticationPrincipal(clock = clock)

        val response = client()
            .mutateWith(mockOpaqueToken().principal(principal))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val cNonce = assertNotNull(cNonceRepository.loadCNonceByAccessToken(token.tokenValue))

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
        val (principal, token) = bearerTokenAuthenticationPrincipal(
            clock = clock,
            scopes = listOf(PidSdJwtVcScope),
        )

        val response = client()
            .mutateWith(mockOpaqueToken().principal(principal))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val cNonce = assertNotNull(cNonceRepository.loadCNonceByAccessToken(token.tokenValue))

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
        val (principal, token) = bearerTokenAuthenticationPrincipal(clock = clock)

        val response = client()
            .mutateWith(mockOpaqueToken().principal(principal))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
            .expectBody<IssueCredentialResponse.FailedTO>()
            .returnResult()
            .responseBody

        val cNonce = assertNotNull(cNonceRepository.loadCNonceByAccessToken(token.tokenValue))

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
     * Verifies issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    @Ignore // TODO The test is currently ignored, it doesn't provide expected proof
    fun `issuance success`() = runTest {
        val (principal, token) = bearerTokenAuthenticationPrincipal(clock = clock)
        val previousCNonce = genCNonce(token.tokenValue, clock)
        cNonceRepository.upsertCNonce(previousCNonce)

        val response = client()
            .mutateWith(mockOpaqueToken().principal(principal))
            .post()
            .uri(WalletApi.CREDENTIAL_ENDPOINT)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody<IssueCredentialResponse.PlainTO>()
            .returnResult()
            .let { assertNotNull(it.responseBody) }

        val newCNonce = checkNotNull(cNonceRepository.loadCNonceByAccessToken(token.tokenValue))
        assertNotEquals(previousCNonce, newCNonce)

        val issuedCredential = assertIs<JsonPrimitive>(response.credential)
        assertTrue(issuedCredential.isString)
        assertNull(response.transactionId)
        assertEquals(newCNonce.nonce, response.nonce)
        assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
    }
}

private fun bearerTokenAuthenticationPrincipal(
    subject: String = "user",
    clock: Clock,
    expiresIn: Duration = Duration.ofMinutes(10L),
    scopes: List<Scope> = listOf(PidMsoMdocScope, PidSdJwtVcScope),
    authorities: List<GrantedAuthority> = listOf(SimpleGrantedAuthority("ROLE_USER")),
): Pair<OAuth2AuthenticatedPrincipal, OAuth2AccessToken> {
    val issuedAt = clock.instant()
    return DefaultOAuth2AuthenticatedPrincipal(
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
    ) to OAuth2AccessToken(TokenType.BEARER, "token", issuedAt, (issuedAt + expiresIn))
}

// FIXME
//  The request doesn't include a correct proof.
//  We need to build a function for creating a JWT proof using x5c
private val request =
    """
        {
          "format": "mso_mdoc",
          "doctype": "eu.europa.ec.eudiw.pid.1",
          "proof": {
            "proof_type": "jwt",
            "jwt": "123321231"
          }
        }
    """.trimIndent()

@Configuration
private class WalletApiTestConfig {

    @Bean
    @Primary
    fun getPidData(): GetPidData =
        GetPidData {
            val pid = Pid(
                familyName = FamilyName("Surname"),
                givenName = GivenName("Firstname"),
                birthDate = LocalDate.of(1989, Month.AUGUST, 22),
                ageOver18 = true,
                uniqueId = UniqueId(UUID.randomUUID().toString()),
            )
            val issuingCountry = IsoCountry("GR")
            val pidMetaData = PidMetaData(
                issuanceDate = DateAndPossiblyTime(LocalDate.now(), null),
                expiryDate = DateAndPossiblyTime(LocalDate.of(2030, 11, 10), null),
                documentNumber = null,
                issuingAuthority = IssuingAuthority.MemberState(issuingCountry),
                administrativeNumber = null,
                issuingCountry = issuingCountry,
                issuingJurisdiction = null,
                portrait = null,
            )
            pid to pidMetaData
        }

    @Bean
    @Primary
    fun validateJwtProof(): ValidateJwtProof =
        RSAKeyGenerator(2048, false)
            .generate()
            .let {
                ValidateJwtProof { _, _, _ ->
                    Result.success(CredentialKey.Jwk(it.toPublicJWK()))
                }
            }
}
