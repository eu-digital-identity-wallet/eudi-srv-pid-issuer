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
import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.raise.either
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestationJWT
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestationRequirement
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyNonce
import java.net.URI
import java.security.cert.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.Instant

internal val SkipRevocation: PKIXParameters.() -> Unit = { isRevocationEnabled = false }

internal class VerifyKeyAttestation(
    private val trustAnchors: NonEmptyList<X509Certificate>? = null,
    private val verifyAttestedKey: VerifyAttestedKey? = null,
    private val maxSkew: Duration = 30.seconds,
    private val verifyNonce: VerifyNonce,
) {
    suspend operator fun invoke(
        keyAttestation: KeyAttestationJWT,
        signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
        keyAttestationRequirement: KeyAttestationRequirement.Required,
        expectExpirationClaim: Boolean,
        at: Instant,
    ): Either<Throwable, Pair<NonEmptyList<JWK>, String>> = either {
        with(keyAttestation) {
            val algorithm = extractSupportedAlgorithm(signingAlgorithmsSupported)
            val key = extractSigningKey()
                .ensureCompatibleWith(algorithm)
                .ensureIsPublicAsymmetricKey()

            val nonce = verifyCNonce(at)
            verifySignature(key, algorithm, expectExpirationClaim)
            ensureMeetsKeyAttestationRequirements(keyAttestationRequirement, nonce)

            keyAttestation.attestedKeys to nonce
        }
    }

    private fun KeyAttestationJWT.extractSigningKey(): JWK {
        val header = jwt.header
        val kid: String? = header.keyID
        val x5c: List<Base64>? = header.x509CertChain

        return when {
            kid != null && x5c.isNullOrEmpty() -> resolveDidUrl(URI.create(kid)).getOrThrow()
            kid == null && !x5c.isNullOrEmpty() -> {
                val chain = X509CertChainUtils.parse(x5c).toNonEmptyListOrNull()
                requireNotNull(chain) { "x5c chain cannot be empty" }
                if (trustAnchors != null) {
                    chain.isTrusted(trustAnchors)
                }
                JWK.parse(chain.head)
            }
            else -> error("Invalid Key attestation : No signing key found in one of 'kid' or 'x5c'. 'trust_chain not yet supported'")
        }
    }

    private suspend fun KeyAttestationJWT.verifyCNonce(at: Instant): String {
        val nonce = jwt.jwtClaimsSet.getStringClaim("nonce")
        requireNotNull(nonce) {
            "Key attestation does not contain a c_nonce."
        }
        require(verifyNonce(nonce, at)) {
            "Invalid c_nonce provided in key attestation JWT"
        }
        return nonce
    }

    private fun KeyAttestationJWT.verifySignature(
        key: AsymmetricJWK,
        algorithm: JWSAlgorithm,
        expectExpirationClaim: Boolean,
    ) {
        val expectedType = JOSEObjectType(OpenId4VciSpec.KEY_ATTESTATION_JWT_TYPE)
        val keySelector = SingleKeyJWSKeySelector<SecurityContext>(algorithm, key.toPublicKey())
        val requiredClaims = if (expectExpirationClaim) {
            setOf("iat", "attested_keys", "exp")
        } else {
            setOf("iat", "attested_keys")
        }
        val processor = DefaultJWTProcessor<SecurityContext>()
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

    private suspend fun KeyAttestationJWT.ensureMeetsKeyAttestationRequirements(
        keyAttestationRequirement: KeyAttestationRequirement.Required,
        nonce: String,
    ) {
        // if key storage constraints are expected, the passed key attestation must meet these constraints
        keyAttestationRequirement.keyStorage?.let {
            requireNotNull(keyStorage) {
                "Key Attestation expected to contain information about the key storage's attack resistance but does not."
            }
            require(keyAttestationRequirement.keyStorage.containsAll(keyStorage)) {
                "The provided key storage's attack resistance does not match the expected one."
            }
        }
        // if user authentication constraints are expected, the passed key attestation must meet these constraints
        keyAttestationRequirement.userAuthentication?.let {
            requireNotNull(userAuthentication) {
                "Key Attestation expected to contain information about the user authentication's attack resistance but does not."
            }
            require(keyAttestationRequirement.userAuthentication.containsAll(userAuthentication)) {
                "The provided user authentication's attack resistance does not match the expected one."
            }
        }
        verifyAttestedKey?.verify(attestedKeys, keyAttestationRequirement, nonce)
            ?.mapLeft {
                error("${it.size} of the total ${attestedKeys.size} attested keys failed to pass verification")
            }
    }
}

private fun KeyAttestationJWT.extractSupportedAlgorithm(signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>): JWSAlgorithm =
    jwt.header.algorithm
        .takeIf(JWSAlgorithm.Family.EC::contains)
        ?.takeIf(signingAlgorithmsSupported::contains)
        ?: error("signing algorithm of key attestation '${jwt.header.algorithm.name}' is not supported")

private fun JWK.ensureCompatibleWith(signingAlgorithm: JWSAlgorithm): JWK {
    val keySupportedAlgorithms =
        when (this) {
            is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
            else -> error("unsupported key type '${keyType.value}'")
        }
    require(signingAlgorithm in keySupportedAlgorithms) {
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

private fun NonEmptyList<X509Certificate>.isTrusted(
    trustAnchors: NonEmptyList<X509Certificate>,
    customizePKIX: PKIXParameters.() -> Unit = SkipRevocation,
) {
    val factory = CertificateFactory.getInstance("X.509")
    val certPath = factory.generateCertPath(this)

    val trust = trustAnchors.map { cert -> TrustAnchor(cert, null) }.toSet()
    val pkixParameters = PKIXParameters(trust).apply(customizePKIX)

    val validator = CertPathValidator.getInstance("PKIX")
    validator.validate(certPath, pkixParameters)
}
