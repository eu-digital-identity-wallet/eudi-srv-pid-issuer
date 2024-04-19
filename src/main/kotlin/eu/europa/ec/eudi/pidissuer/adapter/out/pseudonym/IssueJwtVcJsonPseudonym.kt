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
package eu.europa.ec.eudi.pidissuer.adapter.out.pseudonym

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidDisplay
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
import java.time.Clock
import java.util.*

typealias UserPseudonym = String

val PseudoJwtVcJsonScope: Scope = Scope("pseudonym_jwt_vc_json")

val UserPseudonymAttribute = AttributeDetails(
    name = "user_pseudonym",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "The user pseudonym."),
)

val JwtVcJsonPidConfiguration = JwtVcJsonCredentialConfiguration(
    id = CredentialConfigurationId((PseudoJwtVcJsonScope.value)),
    scope = PseudoJwtVcJsonScope,
    cryptographicBindingMethodsSupported = emptySet(),
    credentialSigningAlgorithmsSupported = emptySet(),
    display = pidDisplay,
    proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
    credentialDefinition = CredentialDefinition(
        type = listOf("VerifiableCredential", "PseudonymCredential"),
        credentialSubject = listOf(UserPseudonymAttribute),
    ),
)

class IssueJwtVcJsonUserPseudonym(
    val credentialIssuerId: CredentialIssuerId,
    private val generateUserPseudonym: GenerateUserPseudonym,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    private val signAlg: JWSAlgorithm,
    private val issuerKey: ECKey,
    private val clock: Clock,
    private val storeIssuedCredential: StoreIssuedCredential,
) : IssueSpecificCredential<JsonElement> {

    private val log = LoggerFactory.getLogger(IssueJwtVcJsonUserPseudonym::class.java)

    override val supportedCredential: JwtVcJsonCredentialConfiguration
        get() = JwtVcJsonPidConfiguration

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

        val jwt = encodePseudonymToJwtVcJson()

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
                log.info("Successfully issued pseudonym")
                log.debug("Issued pseudonym data {}", it)
            }
    }

    private fun encodePseudonymToJwtVcJson(): String {
        val _now = clock.instant()

        val credential = buildCredential {
            credentialMetadata {
                type("PseudonymCredential")
                issuer(credentialIssuerId.value.toString())
                issueDate(_now)
                expirationDate(_now.plusSeconds(86400))
            }
            credentialSubject {
                addClaim("user_pseudonym", generateUserPseudonym())
            }
        }

        val verifiableCredential = JwtVcJsonRealizer().realize(credential, ProofMechanism.JWT(issuerKey, signAlg))
        return verifiableCredential.credential.serialize()
    }

    private fun vcClaim(
        userPseudonym: UserPseudonym,
        supportedCredential: JwtVcJsonCredentialConfiguration,
    ): Map<String, Any> =
        mapOf(
            "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
            "type" to supportedCredential.credentialDefinition.type,
            "credentialSubject" to mapOf(
                "user_pseudonym" to userPseudonym,
            ),
        )

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
