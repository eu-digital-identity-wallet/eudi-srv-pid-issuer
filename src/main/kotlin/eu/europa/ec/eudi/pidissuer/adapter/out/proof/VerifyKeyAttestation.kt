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

import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.status.GetStatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.status.StatusListTokenStatus
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedIssuer
import eu.europa.ec.eudi.pidissuer.port.out.trust.TrustResult
import eu.europa.ec.eudi.pidissuer.port.out.trust.VerificationContext
import java.security.cert.X509Certificate
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.Instant

class VerifyKeyAttestation(
    private val maxSkew: Duration = 30.seconds,
    private val isTrustedIssuer: IsTrustedIssuer,
    private val getStatusListTokenStatus: GetStatusListTokenStatus,
) {
    context(_: Raise<String>, proofType: ProofType.Jwt)
    suspend operator fun invoke(
        keyAttestation: KeyAttestationJWT,
        at: Instant,
    ): Pair<NonEmptyList<ECKey>, String?> =
        invoke(
            keyAttestation,
            proofType.signingAlgorithmsSupported,
            proofType.keyAttestationRequirement,
            expectExpirationClaim = true,
            at,
        )

    context(_: Raise<String>, proofType: ProofType.Attestation)
    suspend operator fun invoke(
        keyAttestation: KeyAttestationJWT,
        at: Instant,
    ): Pair<NonEmptyList<ECKey>, String?> =
        invoke(
            keyAttestation,
            proofType.signingAlgorithmsSupported,
            proofType.keyAttestationRequirement,
            expectExpirationClaim = false,
            at,
        )

    context(_: Raise<String>)
    private suspend operator fun invoke(
        keyAttestation: KeyAttestationJWT,
        signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
        keyAttestationRequirement: KeyAttestationRequirement,
        expectExpirationClaim: Boolean,
        at: Instant,
    ): Pair<NonEmptyList<ECKey>, String?> =
        with(keyAttestation) {
            val nonce = claims.nonce
            val algorithm = extractSupportedAlgorithm(signingAlgorithmsSupported)
            val walletProviderSigningKey = extractSigningKey()
            val key =
                walletProviderSigningKey.key
                    .ensureCompatibleWith(algorithm)
                    .ensureIsPublicAsymmetricKey()
            verifySignature(key, algorithm, expectExpirationClaim)
            ensureMeetsKeyAttestationRequirements(keyAttestationRequirement)
            walletProviderSigningKey.ensureTrustWalletProvider()

            keyAttestation.claims.keyStorageStatus.ensureIsValid()

            keyAttestation.claims.attestedKeys.value to nonce
        }

    context(_: Raise<String>)
    private suspend fun WalletProviderSigningKey.ensureTrustWalletProvider() {
        val result = isTrustedIssuer(x5c, verificationContext = VerificationContext.WalletProviderAttestation)
        ensure(result is TrustResult.IsTrusted) {
            "Key attestation is not issued by a trusted wallet provider"
        }
    }

    context(_: Raise<String>)
    private fun KeyAttestationJWT.extractSigningKey(): WalletProviderSigningKey {
        val header = jwt.header
        val chain =
            ensureNotNull(header.x509CertChain?.toNonEmptyListOrNull()) {
                "Invalid Key attestation: x5c chain cannot be empty"
            }.map { X509CertUtils.parseWithException(it.decode()) }
        val jwk = JWK.parse(chain.head)
        return WalletProviderSigningKey(jwk, chain)
    }

    private fun KeyAttestationJWT.verifySignature(
        key: AsymmetricJWK,
        algorithm: JWSAlgorithm,
        expectExpirationClaim: Boolean,
    ) {
        val expectedType = JOSEObjectType(OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE)
        val keySelector = SingleKeyJWSKeySelector<SecurityContext>(algorithm, key.toPublicKey())
        val requiredClaims =
            if (expectExpirationClaim) {
                setOf("iat", "attested_keys", "exp")
            } else {
                setOf("iat", "attested_keys")
            }
        val processor =
            DefaultJWTProcessor<SecurityContext>()
                .apply {
                    jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(expectedType)
                    jwsKeySelector = keySelector
                    jwtClaimsSetVerifier =
                        DefaultJWTClaimsVerifier<SecurityContext?>(
                            JWTClaimsSet.Builder().build(),
                            requiredClaims,
                        ).apply {
                            maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                        }
                }
        processor.process(jwt, null)
    }

    context(_: Raise<String>)
    private fun KeyAttestationJWT.ensureMeetsKeyAttestationRequirements(keyAttestationRequirement: KeyAttestationRequirement) {
        // if key storage constraints are expected, the passed key attestation must meet these constraints
        keyAttestationRequirement.keyStorage?.let {
            val keyStorage = claims.keyStorage
            ensure(keyAttestationRequirement.keyStorage.containsAll(keyStorage)) {
                "The provided key storage's attack resistance does not match the expected one."
            }
        }
        // if user authentication constraints are expected, the passed key attestation must meet these constraints
        keyAttestationRequirement.userAuthentication?.let {
            val userAuthentication = claims.userAuthentication
            ensure(keyAttestationRequirement.userAuthentication.containsAll(userAuthentication)) {
                "The provided user authentication's attack resistance does not match the expected one."
            }
        }
        claims.attestedKeys
    }

    context(_: Raise<String>)
    private suspend fun KeyStorageStatus.ensureIsValid() {
        val keyStorageStatus =
            withError({ error: GetStatusListTokenStatus.Error ->
                "Unable to verify Key Storage Status: ${error.value.message}"
            }) {
                getStatusListTokenStatus(status.statusList, VerificationContext.WalletOrKeyStorageStatus)
            }
        ensure(StatusListTokenStatus.VALID == keyStorageStatus) {
            "Key Storage Status is not valid"
        }
    }
}

context(_: Raise<String>)
private fun KeyAttestationJWT.extractSupportedAlgorithm(signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>): JWSAlgorithm =
    jwt.header.algorithm
        .takeIf(JWSAlgorithm.Family.EC::contains)
        ?.takeIf(signingAlgorithmsSupported::contains)
        ?: raise("signing algorithm of key attestation '${jwt.header.algorithm.name}' is not supported")

context(_: Raise<String>)
private fun JWK.ensureCompatibleWith(signingAlgorithm: JWSAlgorithm): JWK {
    val keySupportedAlgorithms =
        when (this) {
            is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
            else -> raise("unsupported key type '${keyType.value}'")
        }
    ensure(signingAlgorithm in keySupportedAlgorithms) {
        "key type '${keyType.value}' is not compatible with signing algorithm '${algorithm.name}'"
    }
    return this
}

private fun JWK.ensureIsPublicAsymmetricKey(): AsymmetricJWK {
    require(!isPrivate) {
        "Private key provided in key attestation. Must be a public key."
    }
    require(this is AsymmetricJWK) {
        "Symmetric key provided in key attestation. Must be an asymmetric key."
    }
    return this
}

private data class WalletProviderSigningKey(
    val key: JWK,
    val x5c: NonEmptyList<X509Certificate>,
)
