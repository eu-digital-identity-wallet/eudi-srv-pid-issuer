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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
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
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit

/**
 * Validator for JWT Proofs.
 */
internal class ValidateJwtProof(
    private val credentialIssuerId: CredentialIssuerId,
    private val verifyKeyAttestation: VerifyKeyAttestation,
) {
    suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Jwt,
        credentialConfiguration: CredentialConfiguration,
        at: Instant,
    ): Either<IssueCredentialError.InvalidProof, Pair<CredentialKey, String?>> = either {
        val proofType = credentialConfiguration.proofTypesSupported[ProofTypeEnum.JWT]
        ensureNotNull(proofType) {
            IssueCredentialError.InvalidProof("credential configuration '${credentialConfiguration.id.value}' doesn't support 'jwt' proofs")
        }
        check(proofType is ProofType.Jwt)
        credentialKeyAndNonce(unvalidatedProof, proofType, at).bind()
    }

    private suspend fun credentialKeyAndNonce(
        unvalidatedProof: UnvalidatedProof.Jwt,
        proofType: ProofType.Jwt,
        at: Instant,
    ): Either<IssueCredentialError.InvalidProof, Pair<CredentialKey, String?>> = Either.catch {
        val signedJwt = SignedJWT.parse(unvalidatedProof.jwt)
        val (algorithm, credentialKey) = algorithmAndCredentialKey(signedJwt, proofType, verifyKeyAttestation, at)
        val keySelector = keySelector(signedJwt, credentialKey, algorithm)
        val processor = processor(credentialIssuerId, keySelector)
        val claimSet = processor.process(signedJwt, null)

        credentialKey to claimSet.getStringClaim("nonce")
    }.mapLeft { IssueCredentialError.InvalidProof("Invalid proof JWT", it) }
}

private suspend fun algorithmAndCredentialKey(
    signedJwt: SignedJWT,
    proofType: ProofType.Jwt,
    verifyKeyAttestation: VerifyKeyAttestation,
    at: Instant,
): Pair<JWSAlgorithm, CredentialKey> {
    val supported = proofType.signingAlgorithmsSupported
    val header = signedJwt.header
    val algorithm = header.algorithm
        .takeIf(JWSAlgorithm.Family.SIGNATURE::contains)
        ?.takeIf(supported::contains)
        ?: error("signing algorithm '${header.algorithm.name}' is not supported")

    val kid = header.keyID
    val jwk = header.jwk
    val x5c = header.x509CertChain
    val keyAttestation = header.getCustomParam("key_attestation") as? String

    val key = when {
        kid != null && jwk == null && keyAttestation == null && x5c.isNullOrEmpty() -> CredentialKey.DIDUrl(kid).getOrThrow()
        kid == null && jwk != null && keyAttestation == null && x5c.isNullOrEmpty() -> CredentialKey.Jwk(jwk)
        kid == null && jwk == null && keyAttestation == null && !x5c.isNullOrEmpty() -> CredentialKey.X5c.parseDer(x5c).getOrThrow()
        jwk == null && keyAttestation != null && x5c.isNullOrEmpty() -> {
            CredentialKey.AttestedKeys.fromKeyAttestation(keyAttestation, proofType, verifyKeyAttestation, at)
        }

        else -> error("public key(s) must be provided in one of 'kid', 'jwk', 'x5c' or 'key_attestation'")
    }.apply {
        ensureCompatibleWithAlgorithm(algorithm, signedJwt)
    }

    return (algorithm to key)
}

private suspend fun CredentialKey.AttestedKeys.Companion.fromKeyAttestation(
    keyAttestation: String,
    proofJwt: ProofType.Jwt,
    verifyKeyAttestation: VerifyKeyAttestation,
    at: Instant,
): CredentialKey.AttestedKeys {
    require(proofJwt.keyAttestationRequirement is KeyAttestation.Required) {
        "Proof type JWT does not require key attestation, though one was provided."
    }
    val keyAttestationJWT = KeyAttestationJWT(keyAttestation)
    val attestedKeys = verifyKeyAttestation(
        keyAttestation = keyAttestationJWT,
        signingAlgorithmsSupported = proofJwt.signingAlgorithmsSupported,
        keyAttestationRequirement = proofJwt.keyAttestationRequirement,
        at = at,
    ).getOrThrow()

    return CredentialKey.AttestedKeys(attestedKeys)
}

private suspend fun CredentialKey.ensureCompatibleWithAlgorithm(algorithm: JWSAlgorithm, signedJwt: SignedJWT) {
    fun JWK.ensureCompatibleWith(algorithm: JWSAlgorithm) {
        val supportedAlgorithms =
            when (this) {
                is RSAKey -> RSASSASigner.SUPPORTED_ALGORITHMS
                is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                is OctetKeyPair -> Ed25519Signer.SUPPORTED_ALGORITHMS
                else -> error("unsupported key type '${keyType.value}'")
            }
        require(algorithm in supportedAlgorithms) {
            "key type '${keyType.value}' is not compatible with signing algorithm '${algorithm.name}'"
        }
    }

    when (this) {
        is CredentialKey.DIDUrl -> jwk.ensureCompatibleWith(algorithm)
        is CredentialKey.Jwk -> value.ensureCompatibleWith(algorithm)

        is CredentialKey.AttestedKeys -> {
            val signingJWK = keys.signingKeyOf(signedJwt)
            requireNotNull(signingJWK) { "Key attestation does not contain a key that verifies the jwt proof signature" }
            signingJWK.ensureCompatibleWith(algorithm)
        }

        is CredentialKey.X5c -> {
            val supportedAlgorithms =
                when (certificate.publicKey) {
                    is RSAPublicKey -> RSASSASigner.SUPPORTED_ALGORITHMS
                    is ECPublicKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                    is EdECPublicKey -> Ed25519Signer.SUPPORTED_ALGORITHMS
                    else -> error("unsupported certificate algorithm '${certificate.publicKey.algorithm}'")
                }
            require(algorithm in supportedAlgorithms) {
                "certificate algorithm '${certificate.publicKey.algorithm}' is not compatible with signing algorithm '${algorithm.name}'"
            }
        }
    }
}

private suspend fun keySelector(
    signedJwt: SignedJWT,
    credentialKey: CredentialKey,
    algorithm: JWSAlgorithm,
): JWSKeySelector<SecurityContext> {
    fun <C : SecurityContext> JWK.keySelector(algorithm: JWSAlgorithm): SingleKeyJWSKeySelector<C> =
        when (this) {
            is AsymmetricJWK -> SingleKeyJWSKeySelector(algorithm, toPublicKey())
            else -> TODO("CredentialKey.Jwk with non AsymmetricJWK is not yet supported")
        }

    return when (credentialKey) {
        is CredentialKey.AttestedKeys -> {
            val signingJWK = credentialKey.keys.signingKeyOf(signedJwt)
            requireNotNull(signingJWK) { "Key attestation does not contain a key that verifies the jwt proof signature" }
            signingJWK.keySelector(algorithm)
        }
        is CredentialKey.DIDUrl -> credentialKey.jwk.keySelector(algorithm)
        is CredentialKey.Jwk -> credentialKey.value.keySelector(algorithm)
        is CredentialKey.X5c -> SingleKeyJWSKeySelector(algorithm, credentialKey.certificate.publicKey)
    }
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
