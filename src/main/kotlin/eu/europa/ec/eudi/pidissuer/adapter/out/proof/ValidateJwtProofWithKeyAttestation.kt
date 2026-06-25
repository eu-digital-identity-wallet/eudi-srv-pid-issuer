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
package eu.europa.ec.eudi.pidissuer.adapter.out.proof

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.effect
import arrow.core.raise.fold
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.Instant

/**
 * Validator for JWT Proofs.
 */
class ValidateJwtProofWithKeyAttestation(
    private val credentialIssuerId: CredentialIssuerId,
    private val verifyKeyAttestation: VerifyKeyAttestation,
) : ValidateProof.Validator<UnvalidatedProof.Jwt, ProofType.Jwt> {
    context(_: Raise<IssueCredentialError.InvalidProof>, proofType: ProofType.Jwt)
    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Jwt,
        at: Instant,
    ): KeyAttestation =
        effect { doValidate(unvalidatedProof, at) }
            .fold(
                transform = { it },
                recover = { raise(IssueCredentialError.InvalidProof(it)) },
                catch = { raise(IssueCredentialError.InvalidProof("Invalid proof JWT", it)) },
            )

    context(_: Raise<String>, proofType: ProofType.Jwt)
    private suspend fun doValidate(
        unvalidatedProof: UnvalidatedProof.Jwt,
        at: Instant,
    ): KeyAttestation =
        withContext(Dispatchers.Default) {
            val jwtProof = SignedJWT.parse(unvalidatedProof.jwt)
            val nonce = ensureNotNull(jwtProof.jwtClaimsSet.getStringClaim("nonce")) { "Missing 'nonce'" }
            ensure(jwtProof.header.algorithm in proofType.signingAlgorithmsSupported) {
                "JWT proof signing algorithm '${jwtProof.header.algorithm}' is not supported, " +
                    "must be one of: ${proofType.signingAlgorithmsSupported.joinToString(", ") { it.name }}"
            }
            val (algorithm, credentialKeys, keyStorageStatus) =
                algorithmAndCredentialKey(jwtProof, verifyKeyAttestation, expectedKeyAttestationNonce = nonce, at)
            ensure(jwtProof.header.keyID == ETSI119472Part3.KEY_ATTESTATION_JWT_PROOF_SIGNING_KEY_INDEX.toString()) {
                "JWT Proof with `key_attestation` must contain header `kid` " +
                    "with value `${ETSI119472Part3.KEY_ATTESTATION_JWT_PROOF_SIGNING_KEY_INDEX}`"
            }

            ensure(keyStorageStatus.exp >= at + proofType.keyAttestationRequirement.preferredKeyStorageStatusPeriod.value) {
                "Key Storage Status expiration date does not meet the preferred key storage status period"
            }

            val keySelector = keySelector(credentialKeys, algorithm)
            val processor = processor(credentialIssuerId, keySelector)
            processor.process(jwtProof, null)

            KeyAttestation(
                keys = credentialKeys,
                cNonce = nonce,
                keyStorageStatus = keyStorageStatus,
            )
        }
}

context(_: Raise<String>, proofType: ProofType.Jwt)
private suspend fun algorithmAndCredentialKey(
    jwtProof: SignedJWT,
    verifyKeyAttestation: VerifyKeyAttestation,
    expectedKeyAttestationNonce: String,
    at: Instant,
): Triple<JWSAlgorithm, CredentialKeys, KeyStorageStatus> {
    val supported = proofType.signingAlgorithmsSupported
    val header = jwtProof.header
    val algorithm = header.algorithm
    ensureNotNull(algorithm) { "Missing 'alg' header in JWT Proof" }
    ensure(algorithm in supported) { "signing algorithm '${header.algorithm.name}' is not supported" }

    val keyAttestation = header.getCustomParam("key_attestation") as? String?
    ensureNotNull(keyAttestation) { "JWT Proof must contain `key_attestation`" }

    val (credentialKeys, keyStorageStatus) =
        CredentialKeys.fromKeyAttestation(
            keyAttestation,
            verifyKeyAttestation,
            expectedKeyAttestationNonce,
            at,
        )
    credentialKeys.ensureCompatibleWithAlgorithm(algorithm)

    return Triple(algorithm, credentialKeys, keyStorageStatus)
}

context(_: Raise<String>, proofJwt: ProofType.Jwt)
private suspend fun CredentialKeys.Companion.fromKeyAttestation(
    keyAttestation: String,
    verifyKeyAttestation: VerifyKeyAttestation,
    expectedNonce: String,
    at: Instant,
): Pair<CredentialKeys, KeyStorageStatus> {
    val keyAttestationJWT = KeyAttestationJWT(keyAttestation)
    ensure(keyAttestationJWT.jwt.header.algorithm in proofJwt.signingAlgorithmsSupported) {
        "Key attestation signing algorithm '${keyAttestationJWT.jwt.header.algorithm}' is not supported, " +
            "must be one of: ${proofJwt.signingAlgorithmsSupported.joinToString(", ") { it.name }}"
    }
    val (attestedKeys, nonce) = verifyKeyAttestation(keyAttestationJWT, at)
    if (null != nonce) {
        ensure(expectedNonce == nonce) { "Key Attestation 'nonce' does not match JWT Proof 'nonce'" }
    }

    return CredentialKeys(attestedKeys) to keyAttestationJWT.claims.keyStorageStatus
}

private fun CredentialKeys.ensureCompatibleWithAlgorithm(algorithm: JWSAlgorithm) {
    fun JWK.ensureCompatibleWith(algorithm: JWSAlgorithm) {
        val supportedAlgorithms =
            when (this) {
                is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                else -> error("unsupported key type '${keyType.value}'")
            }
        require(algorithm in supportedAlgorithms) {
            "key type '${keyType.value}' is not compatible with signing algorithm '${algorithm.name}'"
        }
    }

    val signingJWK = value.first()
    signingJWK.ensureCompatibleWith(algorithm)
}

private fun keySelector(
    credentialKeys: CredentialKeys,
    algorithm: JWSAlgorithm,
): JWSKeySelector<SecurityContext> {
    fun <C : SecurityContext> JWK.keySelector(algorithm: JWSAlgorithm): SingleKeyJWSKeySelector<C> =
        when (this) {
            is AsymmetricJWK -> SingleKeyJWSKeySelector(algorithm, toPublicKey())
            else -> TODO("CredentialKey.Jwk with non AsymmetricJWK is not yet supported")
        }
    val signingJWK = credentialKeys.value.first()
    return signingJWK.keySelector(algorithm)
}

private val expectedType = JOSEObjectType("openid4vci-proof+jwt")
private val maxSkew = 30.seconds

private fun processor(
    credentialIssuerId: CredentialIssuerId,
    keySelector: JWSKeySelector<SecurityContext>,
): JWTProcessor<SecurityContext> =
    DefaultJWTProcessor<SecurityContext>()
        .apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(expectedType)
            jwsKeySelector = keySelector
            jwtClaimsSetVerifier =
                DefaultJWTClaimsVerifier<SecurityContext?>(
                    credentialIssuerId.externalForm, // aud
                    JWTClaimsSet.Builder().build(),
                    setOf("iat"),
                ).apply {
                    maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                }
        }
