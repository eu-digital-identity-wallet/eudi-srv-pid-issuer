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
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import java.security.interfaces.ECPublicKey
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.Instant

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
        require(signedJwt.header.algorithm in proofType.signingAlgorithmsSupported) {
            "JWT proof signing algorithm '${signedJwt.header.algorithm}' is not supported, " +
                "must be one of: ${proofType.signingAlgorithmsSupported.joinToString(", ") { it.name }}"
        }
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
        .takeIf(JWSAlgorithm.Family.EC::contains)
        ?.takeIf(supported::contains)
        ?: error("signing algorithm '${header.algorithm.name}' is not supported")

    val kid: String? = header.keyID
    val jwk: JWK? = header.jwk
    val x5c: List<Base64>? = header.x509CertChain
    val keyAttestation = header.getCustomParam("key_attestation") as String?

    when (proofType.keyAttestationRequirement) {
        KeyAttestationRequirement.NotRequired ->
            require(null == keyAttestation) { "JWT Proof cannot contain `key_attestation`" }

        is KeyAttestationRequirement.Required ->
            requireNotNull(keyAttestation) { "JWT Proof must contain `key_attestation`" }
    }

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
    require(proofJwt.keyAttestationRequirement is KeyAttestationRequirement.Required) {
        "Proof type JWT does not require key attestation, though one was provided."
    }
    val keyAttestationJWT = KeyAttestationJWT(keyAttestation)
    require(keyAttestationJWT.jwt.header.algorithm in proofJwt.signingAlgorithmsSupported) {
        "Key attestation signing algorithm '${keyAttestationJWT.jwt.header.algorithm}' is not supported, " +
            "must be one of: ${proofJwt.signingAlgorithmsSupported.joinToString(", ") { it.name }}"
    }
    val (attestedKeys, _) = verifyKeyAttestation(
        keyAttestation = keyAttestationJWT,
        signingAlgorithmsSupported = proofJwt.signingAlgorithmsSupported,
        keyAttestationRequirement = proofJwt.keyAttestationRequirement,
        expectExpirationClaim = true,
        at = at,
    ).getOrThrow()

    return CredentialKey.AttestedKeys(attestedKeys)
}

private suspend fun CredentialKey.ensureCompatibleWithAlgorithm(algorithm: JWSAlgorithm, signedJwt: SignedJWT) {
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
                    is ECPublicKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                    else -> error("Certificate key not supported")
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
