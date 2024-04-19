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
package eu.europa.ec.eudi.pidissuer.adapter.out.w3c

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertTrue

class BuilderTest {

    val json = Json {
        prettyPrint = true
    }

    @Test
    fun `create pseudonym credential`() {
        val issuedAt = Instant.now()
        val expiresOn = issuedAt.plusSeconds(86400)

        val credential = buildCredential {
            context(CONTEXT_CREDENTIAL)
            context(CONTEXT_CREDENTIAL)
            credentialMetadata {
                type(TYPE_VerifiableCredential)
                type(TYPE_VerifiableCredential)

                type("PseudonymCredential")
                type("PseudonymCredential")

                issuer("https://dev.issuer.dev")
                issueDate(issuedAt)
                expirationDate(expiresOn)
                status(
                    CredentialStatus(
                        id = ID("CredentialStatusId"),
                        type = Type("CredentialStatusType"),
                    ),
                )
            }

            credentialSubject {
                id("CredentialSubjectId")
                addClaim("user_pseudonym", "userPseudonym")
            }
        }.also { println(json.encodeToString(it.toJsonObject())) }

        assertTrue("Default credential context $CONTEXT_CREDENTIAL must be included exactly once.") {
            credential.context.filter { it.toString() == CONTEXT_CREDENTIAL }.size == 1
        }
        assertTrue("Credential type $TYPE_VerifiableCredential must be included exactly once.") {
            credential.metadata.type.elements.filter { it.toString() == TYPE_VerifiableCredential }.size == 1
        }
        assertTrue("Credential type PseudonymCredential must be included exactly once.") {
            credential.metadata.type.elements.filter { it.toString() == "PseudonymCredential" }.size == 1
        }
        assertTrue("Issuer not set properly.") {
            credential.metadata.issuer.toString() == "https://dev.issuer.dev"
        }
        assertTrue("issuanceDate not set properly.") {
            credential.metadata.issuanceDate == issuedAt
        }
        assertTrue("expirationDate not set properly.") {
            credential.metadata.expirationDate == expiresOn
        }
        assertTrue("Status id not set properly.") {
            credential.metadata.status?.id.toString() == "CredentialStatusId"
        }
        assertTrue("Status type not set properly.") {
            val type = credential.metadata.status?.type
            type != null && type.elements.toString().contains("CredentialStatusType")
        }
        assertTrue("Credential subject id not set properly.") {
            credential.credentialSubject[0].id?.toString() == "CredentialSubjectId"
        }
        assertTrue("Claim user_pseudonym missing") {
            credential.credentialSubject[0].claims.find { it.first == "user_pseudonym" } != null
        }
    }
}
