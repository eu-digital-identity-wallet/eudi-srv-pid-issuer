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
package eu.europa.ec.eudi.pidissuer.adapter.out.diploma

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.did.DidMethod
import eu.europa.ec.eudi.pidissuer.adapter.out.did.createDidUrl
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.w3c.JwtVcJsonRealizer
import eu.europa.ec.eudi.pidissuer.adapter.out.w3c.ProofMechanism
import eu.europa.ec.eudi.pidissuer.adapter.out.w3c.buildCredential
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.encodeToJsonElement
import java.time.Clock

class EncodeDiplomaInJwtVcJson(
    private val credentialIssuerId: CredentialIssuerId,
    private val issuerSigningKey: IssuerSigningKey,
    private val clock: Clock,
) {

    operator fun invoke(diploma: Diploma, holderKey: JWK): String {
        val issuedAt = clock.instant()

        val (diplomaName, achieved, entitledTo, performed) = diploma

        val credential = buildCredential {
            credentialMetadata {
                type(diplomaName)
                issuer(credentialIssuerId.value.toString())
                issueDate(issuedAt)
                expirationDate(issuedAt.plusSeconds(86400))
            }
            credentialSubject {
                val didUrl = createDidUrl(holderKey, DidMethod.KEY).getOrThrow()
                id(didUrl.toString())
                addClaim("archived", achieved.toJsonElement())
                entitledTo?.let {
                    addClaim("entitledTo", entitledTo.toJsonElement())
                }
                performed?.let {
                    addClaim("performed", performed.toJsonElement())
                }
            }
        }

        val verifiableCredential = JwtVcJsonRealizer().realize(
            credential,
            ProofMechanism.JWT(issuerSigningKey.key, issuerSigningKey.signingAlgorithm),
        )
        return verifiableCredential.credential.serialize()
    }
}

private fun AchievedClaim.toJsonElement(): JsonElement =
    buildJsonArray {
        learningAchievements.forEach { add(Json.encodeToJsonElement(it)) }
    }

private fun EntitledToClaim.toJsonElement(): JsonElement =
    buildJsonArray {
        entitlements.forEach { add(Json.encodeToJsonElement(it)) }
    }

private fun PerformedClaim.toJsonElement(): JsonElement =
    buildJsonArray {
        learningActivities.forEach { add(Json.encodeToJsonElement(it)) }
    }
