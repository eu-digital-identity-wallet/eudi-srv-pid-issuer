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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.domain.pid.PidSdJwtVcV1
import eu.europa.ec.eudi.pidissuer.domain.pid.asSdObjectAt
import eu.europa.ec.eudi.pidissuer.port.out.jose.ValidateJwtProof
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import eu.europa.ec.eudi.sdjwt.*
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.put
import java.net.URL
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val signAlg: JWSAlgorithm,
    val issuerKey: ECKey,
    private val getPidData: GetPidData,
    private val validateJwtProof: ValidateJwtProof,
) : IssueSpecificCredential(PidSdJwtVcV1) {

    private val issuer: SdJwtVCIssuer by lazy {
        val cfg = IssuerConfig(
            issuerName = credentialIssuerId.value,
            clock = clock,
            hashAlgorithm = hashAlgorithm,
            signAlg = signAlg,
            issuerKey = issuerKey,
        )
        SdJwtVCIssuer(cfg)
    }

    context(Raise<Err>) override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> {
        val holderPubKey = holderPubKey(request.unvalidatedProof, expectedCNonce).value
        val verifiableCredential = selectivelyDisclosedData(authorizationContext)
        val internalReq = SdJwtVCIssuanceRequest(
            type = (supportedCredential as SdJwtVcMetaData).type.value,
            subject = null,
            verifiableCredential = verifiableCredential,
            holderPubKey = holderPubKey,
            expiresAt = null,
            notUseBefore = null,
        )
        val sdJwt = issuer.issue(internalReq)
        return CredentialResponse.Issued(JsonPrimitive(sdJwt))
    }

    context(Raise<Err>)
    private fun holderPubKey(
        unvalidatedProof: UnvalidatedProof,
        expectedCNonce: CNonce,
    ): CredentialKey.Jwk {
        ensure(unvalidatedProof is UnvalidatedProof.Jwt) { Err.Unexpected("Supporting only JWT proof") }
        val algs = supportedCredential.cryptographicBindingMethodsSupported.mapNotNull {
            when (it) {
                is CryptographicBindingMethod.Jwk -> it.cryptographicSuitesSupported
                else -> null
            }
        }.flatten().toNonEmptySetOrNull()
        ensureNotNull(algs) { Err.Unexpected("Cannot find supported signing algs for proofs") }

        val key = validateJwtProof(unvalidatedProof, expectedCNonce, algs).getOrElse {
            raise(Err.Unexpected("Proof is not valid"))
        }
        return key as CredentialKey.Jwk
    }

    context(Raise<Err>)
    private suspend fun selectivelyDisclosedData(
        authorizationContext: AuthorizationContext,
    ): TimeDependant<SdObject> {
        val pid = getPidData(accessToken = authorizationContext.accessToken)
        ensureNotNull(pid) { Err.Unexpected("Cannot obtain PID data") }
        return pid::asSdObjectAt
    }
}

private typealias TimeDependant<F> = (ZonedDateTime) -> F

private data class IssuerConfig(
    val issuerName: URL,
    val clock: Clock = Clock.systemDefaultZone(),
    val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_256,
    val issuerKey: ECKey,
    val signAlg: JWSAlgorithm = JWSAlgorithm.ES256,
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
    val expiresAt: TimeDependant<Instant>? = null,
    val notUseBefore: TimeDependant<Instant>? = null,
)

/**
 * An SD-JWT issuer according to SD-JWT VC
 *
 *
 * See [SD-JWT-VC](https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc-00/draft-ietf-oauth-sd-jwt-vc.html)
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
     * Mandatory claims are: `type`, `iss`, `iat`, `cnf`
     * Optional claims are: `sub`, `exp`, `nbf`
     *
     * **See** [here](https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc-00/draft-ietf-oauth-sd-jwt-vc.html#name-registered-jwt-claims)
     */
    private fun SdJwtVCIssuanceRequest.standardClaimsAt(iat: ZonedDateTime): SdObject =
        buildSdObject {
            plain {
                put("type", type)
                iss(config.issuerName.toExternalForm())
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
            // Check [here](https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc-00/draft-ietf-oauth-sd-jwt-vc.html#name-header-parameters)
            keyID(config.issuerKey.keyID)
            type(JOSEObjectType("vc+sd-jwt"))
        }
    }
}
