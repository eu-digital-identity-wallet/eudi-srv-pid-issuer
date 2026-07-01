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

import arrow.core.nonEmptySetOf
import arrow.core.raise.effect
import arrow.core.raise.fold
import arrow.core.raise.getOrElse
import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import kotlinx.coroutines.test.runTest
import org.springframework.beans.factory.annotation.Autowired
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

@PidIssuerApplicationTest
class CreateCredentialsOfferTest {
    @Autowired
    private lateinit var credentialIssuerMetadata: CredentialIssuerMetaData

    @Autowired
    private lateinit var createCredentialsOffer: CreateCredentialsOffer

    @Test
    fun `credential offer must be created when using an allowed credential offer uri scheme`() =
        runTest {
            val schemes =
                nonEmptySetOf(
                    "https",
                    "openid-credential-offer",
                    "haip-vci",
                    "eu-eaa-offer",
                ).flatMap { nonEmptySetOf(it, it.uppercase()) }

            schemes.forEach { scheme ->
                effect {
                    val credentialConfigurationIds = nonEmptySetOf(credentialIssuerMetadata.credentialConfigurationsSupported.first().id)
                    val uri =
                        createCredentialsOffer(
                            CreateCredentialsOffer.Request(
                                credentialConfigurationIds,
                                "$scheme://",
                            ),
                        )
                    assertTrue { scheme.equals(uri.scheme, ignoreCase = true) }
                }.getOrElse {
                    fail("Failed to create credential offer with scheme $scheme, error: $it")
                }
            }
        }

    @Test
    fun `credential offer must not be created when not using an allowed credential offer uri scheme`() =
        runTest {
            val customCredentialsOfferUris =
                nonEmptySetOf(
                    "javascript://%0aalert('Hacked');//",
                    "data:text/html,<script>alert(1)</script>",
                    "vbscript:msgbox(1)",
                    "file:///etc/passwd",
                    "http://attacker.example/",
                    "//example.com",
                )

            customCredentialsOfferUris.forEach { customCredentialsOfferUri ->
                effect {
                    val credentialConfigurationIds = nonEmptySetOf(credentialIssuerMetadata.credentialConfigurationsSupported.first().id)
                    createCredentialsOffer(
                        CreateCredentialsOffer.Request(
                            credentialConfigurationIds,
                            customCredentialsOfferUri,
                        ),
                    )
                }.fold(
                    transform = { fail("Credential Offer must not be created with uri $it") },
                    recover = {
                        val error = assertIs<CreateCredentialsOffer.Error.InvalidCredentialsOfferUri>(it)
                        val cause = assertIs<IllegalArgumentException>(error.cause)
                        val message = assertNotNull(cause.message)
                        assertTrue { "credentialsOfferUri must use one of the following schemes" in message }
                    },
                )
            }
        }
}
