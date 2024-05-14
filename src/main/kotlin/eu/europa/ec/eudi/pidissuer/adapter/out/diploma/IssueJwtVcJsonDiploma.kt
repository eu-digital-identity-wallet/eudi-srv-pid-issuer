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

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.did.DidMethod
import eu.europa.ec.eudi.pidissuer.adapter.out.did.createDidUrl
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.w3c.JwtVcJsonRealizer
import eu.europa.ec.eudi.pidissuer.adapter.out.w3c.ProofMechanism
import eu.europa.ec.eudi.pidissuer.adapter.out.w3c.buildCredential
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.net.URI
import java.time.Clock
import java.util.Locale.ENGLISH

val DiplomaJwtVcJsonScope: Scope = Scope("diploma_jwt_vc_json")

val diplomaDisplay = listOf(
    CredentialDisplay(
        name = DisplayName("University Degree", ENGLISH),
        logo = ImageUri(
            uri = URI.create("https://examplestate.com/public/diploma.png"),
            alternativeText = "A square figure of a Diploma",
        ),
    ),
)

val IssueJwtVcJsonDiplomaConfiguration = JwtVcJsonCredentialConfiguration(
    id = CredentialConfigurationId((DiplomaJwtVcJsonScope.value)),
    scope = DiplomaJwtVcJsonScope,
    cryptographicBindingMethodsSupported = emptySet(),
    credentialSigningAlgorithmsSupported = emptySet(),
    display = diplomaDisplay,
    proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
    credentialDefinition = CredentialDefinition(
        type = listOf("VerifiableCredential", "UniversityDegreeCredential"),
        credentialSubject = listOf(
            AchievedClaim.attribute,
            EntitledToClaim.attribute,
            PerformedClaim.attribute,
        ),
    ),
)

class IssueJwtVcJsonDiploma(
    val credentialIssuerId: CredentialIssuerId,
    private val generateUserDiplomaData: GenerateUserDiplomaData,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    private val issuerSigningKey: IssuerSigningKey,
    private val clock: Clock,
    private val storeIssuedCredential: StoreIssuedCredential,
) : IssueSpecificCredential<JsonElement> {

    private val log = LoggerFactory.getLogger(IssueJwtVcJsonDiploma::class.java)

    override val supportedCredential: JwtVcJsonCredentialConfiguration
        get() = IssueJwtVcJsonDiplomaConfiguration

    override val publicKey: JWK? = null

    private val validateProof = ValidateProof(credentialIssuerId)

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }

        val jwt = encodeDiplomaToJwtVcJson(holderPubKey.await())

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null

        storeIssuedCredential(
            IssuedCredential(
                format = JWT_VC_JSON_FORMAT,
                type = supportedCredential.credentialDefinition.type.joinToString(" "),
                holder = holderPubKey.await().toPublicJWK().computeThumbprint().toString(),
                holderPublicKey = holderPubKey.await().toPublicJWK(),
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(JsonPrimitive(jwt), notificationId)
            .also {
                log.info("Successfully issued diploma")
                log.debug("Diploma data {}", it)
            }
    }

    private fun encodeDiplomaToJwtVcJson(holderKey: JWK): String {
        val _now = clock.instant()

        val (diplomaName, achieved, entitledTo, performed) = generateUserDiplomaData()

        val credential = buildCredential {
            credentialMetadata {
                type(diplomaName)
                issuer(credentialIssuerId.value.toString())
                issueDate(_now)
                expirationDate(_now.plusSeconds(86400))
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

    context(Raise<InvalidProof>)
    private suspend fun holderPubKey(
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): JWK {
        val key = validateProof(request.unvalidatedProof, expectedCNonce, supportedCredential)
        return extractJwkFromCredentialKey(key)
            .getOrElse {
                raise(InvalidProof("Unable to extract JWK from CredentialKey", it))
            }
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
