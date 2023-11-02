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
package eu.europa.ec.eudi.pidissuer.adapter.out.sdjwt

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateJwtProof
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.sdjwt.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.put
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime

typealias TimeDependant<F> = (ZonedDateTime) -> F

private data class IssuerConfig(
    val credentialIssuerId: CredentialIssuerId,
    val clock: Clock,
    val hashAlgorithm: HashAlgorithm,
    val issuerKey: ECKey,
    val signAlg: JWSAlgorithm,
)

/**
 * Represents a request placed to the issuer, for issuing an SD-JWT
 * @param type The type of the credential
 * @param subject The subject of the SD-JWT. If provided, it will populate the `sub` JWT claim (always disclosable)
 * @param verifiableCredential function that given a point in time returns the verifiable credential expressed
 * as a [SD-JWT specification][SdObject]
 * @param holderPubKey the public key of the holder. Will be included as an always disclosable claim under `cnf`
 * @param expiresAt a function that given a point in time (`iat`) returns the expiration time. If provided,
 * it will be used to populate the `exp` JWT Claim (always disclosable)
 * @param notUseBefore a function that given a point in time (`iat`) returns the "not use before" time. If provided,
 *  * it will be used to populate the `nbf` JWT Claim (always disclosable)
 */
private data class SdJwtVCIssuanceRequest(
    val type: String,
    val subject: String? = null,
    val verifiableCredential: TimeDependant<SdObject>,
    val holderPubKey: JWK,
    val expiresAt: TimeDependant<Instant>?,
    val notUseBefore: TimeDependant<Instant>?,
)

/**
 * An SD-JWT issuer according to SD-JWT VC
 *
 *
 * See [SD-JWT-VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html)
 */
private class SdJwtVCIssuer(private val config: IssuerConfig) {

    fun issue(request: SdJwtVCIssuanceRequest): String {
        val now = now()
        val sdJwtSpec = request.verifiableCredentialAt(now) + request.standardClaimsAt(now)
        val issuedSdJwt = issuer.issue(sdJwtSpec).getOrThrow()
        return issuedSdJwt.serialize()
    }

    private fun now(): ZonedDateTime = ZonedDateTime.ofInstant(config.clock.instant(), config.clock.zone)

    private fun SdJwtVCIssuanceRequest.verifiableCredentialAt(iat: ZonedDateTime): SdObject =
        verifiableCredential(iat)

    /**
     * According to SD-JWT-VC,there are some registered JWT claims
     * that must always be disclosable (plain claims).
     * Mandatory claims are: `vct`, `iss`, `iat`, `cnf`
     * Optional claims are: `sub`, `exp`, `nbf`
     *
     * **See** [here](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#name-verifiable-credential-type-)
     */
    private fun SdJwtVCIssuanceRequest.standardClaimsAt(iat: ZonedDateTime): SdObject =
        buildSdObject {
            plain {
                put("vct", type)
                iss(config.credentialIssuerId.externalForm)
                iat(iat.toInstant().epochSecond)
                subject?.let { sub(it) }
                expiresAt?.let { provider ->
                    val exp = provider(iat)
                    require(exp.epochSecond > iat.toInstant().epochSecond) { "exp should be after iat" }
                    exp(exp.epochSecond)
                }
                notUseBefore?.let { calculateNbf ->
                    val nbf = calculateNbf(iat)
                    require(nbf.epochSecond > iat.toInstant().epochSecond) { "nbe should be after iat" }
                    nbf(nbf.epochSecond)
                }
            }
            cnf(holderPubKey)
        }

    /**
     * Creates a Nimbus-based SD-JWT issuer
     * according to the requirements of SD-JWT VC
     * - No decoys
     * - JWS header kid should contain the id of issuer's key
     * - JWS header typ should contain value "vs+sd-jwt"
     * In addition the issuer will use the [config] to select
     * [HashAlgorithm], [JWSAlgorithm] and [issuer's key][ECKey]
     */
    private val issuer: SdJwtIssuer<SignedJWT> by lazy {
        // SD-JWT VC requires no decoys

        val sdJwtFactory = SdJwtFactory(hashAlgorithm = config.hashAlgorithm, numOfDecoysLimit = 0)
        val signer = ECDSASigner(config.issuerKey)
        SdJwtIssuer.nimbus(sdJwtFactory, signer, config.signAlg) {
            // SD-JWT VC requires the kid & typ header attributes
            // Check [here](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#name-jose-header)
            keyID(config.issuerKey.keyID)
            type(JOSEObjectType("vc+sd-jwt"))
        }
    }
}

fun <DATA> createSdJwtVcIssuer(
    supportedCredential: SdJwtVcMetaData,
    credentialIssuerId: CredentialIssuerId,
    clock: Clock,
    validateJwtProof: ValidateJwtProof,
    extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    hashAlgorithm: HashAlgorithm,
    signAlg: JWSAlgorithm,
    issuerKey: ECKey,
    expiresAt: TimeDependant<Instant>? = null,
    notUseBefore: TimeDependant<Instant>? = null,
    getData: suspend (AuthorizationContext) -> DATA?,
    createSdJwt: (DATA) -> TimeDependant<SdObject>,
): IssueSpecificCredential<JsonElement> = object : IssueSpecificCredential<JsonElement> {
    override val supportedCredential: CredentialMetaData
        get() = supportedCredential

    private val issuer: SdJwtVCIssuer by lazy {
        val cfg = IssuerConfig(
            credentialIssuerId = credentialIssuerId,
            clock = clock,
            hashAlgorithm = hashAlgorithm,
            signAlg = signAlg,
            issuerKey = issuerKey,
        )
        SdJwtVCIssuer(cfg)
    }

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        suspend fun selectivelyDisclosedData(): TimeDependant<SdObject> {
            val data = getData(authorizationContext)
            ensureNotNull(data) { Unexpected("Cannot obtain data") }
            return createSdJwt(data)
        }

        suspend fun holderPubKey(): JWK {
            val key =
                when (val proof = request.unvalidatedProof) {
                    is UnvalidatedProof.Jwt ->
                        validateJwtProof(
                            proof,
                            expectedCNonce,
                            supportedCredential.cryptographicSuitesSupported(),
                        ).getOrElse { raise(InvalidProof("Proof is not valid", it)) }

                    is UnvalidatedProof.Cwt -> raise(InvalidProof("Supporting only JWT proof"))
                }

            return extractJwkFromCredentialKey(key)
                .getOrElse {
                    raise(InvalidProof("Unable to extract JWK from CredentialKey", it))
                }
        }

        val holderPubKey = async(Dispatchers.Default) { holderPubKey() }
        val vcData = async { selectivelyDisclosedData() }

        val internalReq = SdJwtVCIssuanceRequest(
            type = supportedCredential.type.value,
            subject = null,
            verifiableCredential = vcData.await(),
            holderPubKey = holderPubKey.await(),
            expiresAt = expiresAt,
            notUseBefore = notUseBefore,
        )
        val sdJwt = issuer.issue(internalReq)
        CredentialResponse.Issued(JsonPrimitive(sdJwt))
    }
}
