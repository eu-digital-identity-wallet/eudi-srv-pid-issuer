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

import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerContext
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.pid.*
import eu.europa.ec.eudi.pidissuer.port.input.CredentialErrorTypeTo
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialResponse
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenCNonce
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromStream
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
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
import org.springframework.test.web.reactive.server.WebTestClient
import java.io.ByteArrayInputStream
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.Month
import java.util.*
import kotlin.properties.Delegates

@PidIssuerApplicationTest(classes = [WalletApiTestConfig::class])
@OptIn(ExperimentalSerializationApi::class)
internal class WalletApiTest {

    @Autowired
    private lateinit var applicationContext: ApplicationContext

    @Autowired
    private lateinit var context: CredentialIssuerContext

    @Autowired
    private lateinit var cNonceRepository: InMemoryCNonceRepository

    @Autowired
    private lateinit var genCNonce: GenCNonce

    private var client by Delegates.notNull<WebTestClient>()

    @BeforeEach
    internal fun setup() {
        client = WebTestClient.bindToApplicationContext(applicationContext)
            .apply(springSecurity())
            .configureClient()
            .build()

        runBlocking {
            cNonceRepository.clear()
        }
    }

    /**
     * Verifies credential endpoint is not accessible by anonymous users.
     * No CNonce is expected to be generated.
     */
    @Test
    internal fun `requires authorization`() {
        runBlocking {
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
            client.post()
                .uri(WalletApi.CREDENTIAL_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isUnauthorized()
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
        }
    }

    /**
     * Verifies that unknown credential formats cannot be deserialized.
     * Application is expected to fail.
     * No CNonce is expected to be generated.
     */
    @Test
    internal fun `fails with unknown credential request format`() {
        val request = """
            {
              "format": "pid"
            }
        """.trimIndent()

        val (principal, _) = bearerTokenAuthenticationPrincipal(issuedAt = context.clock.instant())
        runBlocking {
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
            client
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
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
        }
    }

    /**
     * Verifies that proof of possession is required.
     * Application is expected to fail.
     * CNonce is expected to be generated.
     */
    @Test
    internal fun `fails when proof is not provided`() {
        val request = """
            {
              "format": "mso_mdoc",
              "doctype": "eu.europa.ec.eudiw.pid.1"
            }
        """.trimIndent()

        val (principal, token) = bearerTokenAuthenticationPrincipal(issuedAt = context.clock.instant())
        runBlocking {
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
            val response = client
                .mutateWith(mockOpaqueToken().principal(principal))
                .post()
                .uri(WalletApi.CREDENTIAL_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .expectBody()
                .returnResult()
                .let {
                    val body = it.responseBody
                    Assertions.assertNotNull(body)
                    Json.decodeFromStream<IssueCredentialResponse.FailedTO>(ByteArrayInputStream(body))
                }

            val cNonce = cNonceRepository.invoke(token.tokenValue)
            Assertions.assertNotNull(cNonce)
            cNonce!!

            Assertions.assertEquals(
                IssueCredentialResponse.FailedTO(
                    CredentialErrorTypeTo.INVALID_PROOF,
                    "The Credential Request must include Proof of Possession",
                    cNonce.nonce,
                    cNonce.expiresIn.toSeconds(),
                ),
                response,
            )
        }
    }

    /**
     * Verifies that when an incorrect scope is used, issuance fails.
     * Application is expected to fail.
     * CNonce is expected to be generated.
     */
    @Test
    internal fun `fails when using incorrect scope`() {
        val (principal, token) = bearerTokenAuthenticationPrincipal(
            issuedAt = context.clock.instant(),
            scopes = listOf(PidSdJwtVcScope),
        )
        runBlocking {
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
            val response = client
                .mutateWith(mockOpaqueToken().principal(principal))
                .post()
                .uri(WalletApi.CREDENTIAL_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .expectBody()
                .returnResult()
                .let {
                    val body = it.responseBody
                    Assertions.assertNotNull(body)
                    Json.decodeFromStream<IssueCredentialResponse.FailedTO>(ByteArrayInputStream(body))
                }

            val cNonce = cNonceRepository.invoke(token.tokenValue)
            Assertions.assertNotNull(cNonce)
            cNonce!!

            Assertions.assertEquals(
                IssueCredentialResponse.FailedTO(
                    CredentialErrorTypeTo.INVALID_REQUEST,
                    "Wrong scope. Expecting $PidMsoMdocScope",
                    cNonce.nonce,
                    cNonce.expiresIn.toSeconds(),
                ),
                response,
            )
        }
    }

    /**
     * Verifies that when a CNonce is not active for the provided Access Token, issuance fails.
     * Application is expected to fail.
     * CNonce is expected to be generated.
     */
    @Test
    internal fun `fails when using no c_nonce is active`() {
        val (principal, token) = bearerTokenAuthenticationPrincipal(issuedAt = context.clock.instant())
        runBlocking {
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
            val response = client
                .mutateWith(mockOpaqueToken().principal(principal))
                .post()
                .uri(WalletApi.CREDENTIAL_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .expectBody()
                .returnResult()
                .let {
                    val body = it.responseBody
                    Assertions.assertNotNull(body)
                    Json.decodeFromStream<IssueCredentialResponse.FailedTO>(ByteArrayInputStream(body))
                }

            val cNonce = cNonceRepository.invoke(token.tokenValue)
            Assertions.assertNotNull(cNonce)
            cNonce!!

            Assertions.assertEquals(
                IssueCredentialResponse.FailedTO(
                    CredentialErrorTypeTo.INVALID_PROOF,
                    "The Credential Request must include Proof of Possession",
                    cNonce.nonce,
                    cNonce.expiresIn.toSeconds(),
                ),
                response,
            )
        }
    }

    /**
     * Verifies issuance success.
     * Creates a CNonce value before doing the request.
     * Does the request.
     * Verifies a new CNonce has been generated.
     * Verifies response values.
     */
    @Test
    internal fun `issuance success`() {
        val (principal, token) = bearerTokenAuthenticationPrincipal(issuedAt = context.clock.instant())
        runBlocking {
            cNonceRepository.verify {
                Assertions.assertTrue(it.isEmpty())
            }
            val previousCNonce = genCNonce(token.tokenValue, context.clock)
            cNonceRepository.invoke(previousCNonce)

            val response = client
                .mutateWith(mockOpaqueToken().principal(principal))
                .post()
                .uri(WalletApi.CREDENTIAL_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .let {
                    val body = it.responseBody
                    Assertions.assertNotNull(body)
                    Json.decodeFromStream<IssueCredentialResponse.PlainTO>(ByteArrayInputStream(body))
                }

            val newCNonce = cNonceRepository.invoke(token.tokenValue)
            Assertions.assertNotNull(newCNonce)
            newCNonce!!
            Assertions.assertNotEquals(previousCNonce, newCNonce)

            val issuedCredential = Assertions.assertInstanceOf(JsonPrimitive::class.java, response.credential)
            Assertions.assertTrue(issuedCredential.isString)
            Assertions.assertNull(response.transactionId)
            Assertions.assertEquals(newCNonce.nonce, response.nonce)
            Assertions.assertEquals(newCNonce.expiresIn.seconds, response.nonceExpiresIn)
        }
    }
}

private fun bearerTokenAuthenticationPrincipal(
    subject: String = "user",
    issuedAt: Instant,
    expiresIn: Duration = Duration.ofMinutes(10L),
    scopes: List<Scope> = listOf(PidMsoMdocScope, PidSdJwtVcScope),
    authorities: List<GrantedAuthority> = listOf(SimpleGrantedAuthority("ROLE_USER")),
): Pair<OAuth2AuthenticatedPrincipal, OAuth2AccessToken> =
    DefaultOAuth2AuthenticatedPrincipal(
        subject,
        mapOf(
            OAuth2TokenIntrospectionClaimNames.USERNAME to subject,
            OAuth2TokenIntrospectionClaimNames.ACTIVE to true,
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
            Pid(
                familyName = FamilyName("Surname"),
                givenName = GivenName("Firstname"),
                birthDate = LocalDate.of(1989, Month.AUGUST, 22),
                ageOver18 = true,
                uniqueId = UniqueId(UUID.randomUUID().toString()),
            )
        }
}
