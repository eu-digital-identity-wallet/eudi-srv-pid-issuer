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

import arrow.core.*
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestation
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestationJWT
import eu.europa.ec.eudi.pidissuer.port.out.credential.VerifyCNonce
import java.net.URI
import java.security.KeyStore
import java.security.cert.*
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit

internal val SkipRevocation: PKIXParameters.() -> Unit = { isRevocationEnabled = false }

internal class VerifyKeyAttestation(
    private val trustAnchors: KeyStore? = null,
    private val verifyAttestedKey: (JWK) -> JWK?,
    private val maxSkew: Duration = 30.seconds,
    private val expectExpirationClaim: Boolean = false,
    private val verifyCNonce: VerifyCNonce,
) {
    suspend operator fun invoke(
        keyAttestation: KeyAttestationJWT,
        signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
        keyAttestationRequirement: KeyAttestation.Required,
        at: Instant,
    ): Either<Throwable, NonEmptyList<JWK>> = Either.catch {
        with(keyAttestation) {
            val algorithm = extractSupportedAlgorithm(signingAlgorithmsSupported)
            val key = extractSigningKey().also {
                it.ensureCompatibleWith(algorithm)
                require(!it.isPrivate) {
                    "Private key provided in key attestation. Must be a public key."
                }
            }
            require(key is AsymmetricJWK) {
                "Symmetric key provided in key attestation. Must be an asymmetric key."
            }
            verifyCNonce(at)
            verifySignature(key, algorithm)
            ensureMeetsKeyAttestationRequirements(keyAttestationRequirement)
        }
        keyAttestation.attestedKeys
    }

    private fun KeyAttestationJWT.extractSigningKey(): JWK {
        val header = jwt.header
        val kid = header.keyID
        val x5c = header.x509CertChain

        return when {
            kid != null && x5c.isNullOrEmpty() -> resolveDidUrl(URI.create(kid)).getOrThrow()
            kid == null && !x5c.isNullOrEmpty() -> {
                trustAnchors?.let {
                    val chain = x5c.map { X509CertUtils.parse(it.decode()) }
                    chain.isTrusted(it)
                }
                parseDer(x5c).getOrThrow()
            }
            else -> error("Invalid Key attestation : No signing key found in one of 'kid' or 'x5c'. 'trust_chain not yet supported'")
        }
    }

    private suspend fun KeyAttestationJWT.verifyCNonce(at: Instant) {
        jwt.jwtClaimsSet.getStringClaim("nonce")?.let { nonce ->
            require(verifyCNonce(nonce, at)) {
                "Invalid c_nonce provided in key attestation JWT"
            }
        }
    }

    private fun KeyAttestationJWT.verifySignature(
        key: AsymmetricJWK,
        algorithm: JWSAlgorithm,
    ) {
        val expectedType = JOSEObjectType(KeyAttestationJWT.KEY_ATTESTATION_JWT_TYPE)
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

    private fun KeyAttestationJWT.ensureMeetsKeyAttestationRequirements(keyAttestationRequirement: KeyAttestation.Required) {
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
        attestedKeys.forEach { key ->
            requireNotNull(verifyAttestedKey(key)) {
                "Key Attestation contains key(s) that cannot be verified as attested."
            }
        }
    }
}

private fun KeyAttestationJWT.extractSupportedAlgorithm(signingAlgorithmsSupported: NonEmptySet<JWSAlgorithm>): JWSAlgorithm =
    jwt.header.algorithm
        .takeIf(JWSAlgorithm.Family.SIGNATURE::contains)
        ?.takeIf(signingAlgorithmsSupported::contains)
        ?: error("signing algorithm of key attestation '${jwt.header.algorithm.name}' is not supported")

private fun JWK.ensureCompatibleWith(algorithm: JWSAlgorithm) {
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

private fun KeyStore.trustedCAs(): List<X509Certificate> {
    fun x509(alias: String) =
        alias.takeIf(::isCertificateEntry)
            ?.let(::getCertificate) as? X509Certificate

    return buildList {
        for (alias in aliases()) {
            x509(alias)?.let(::add)
        }
    }
}

private fun List<X509Certificate>.isTrusted(trustAnchors: KeyStore) {
    val trustedCAs = trustAnchors.trustedCAs().toNonEmptyListOrNull()
    requireNotNull(trustedCAs) { "Empty trust anchors keystore passed" }
    trustOrThrow(toNonEmptyListOrNull()!!, trustedCAs)
}

private fun trustOrThrow(
    chain: Nel<X509Certificate>,
    rootCACertificates: NonEmptyList<X509Certificate>,
    customizePKIX: PKIXParameters.() -> Unit = SkipRevocation,
) {
    val factory = CertificateFactory.getInstance("X.509")
    val certPath = factory.generateCertPath(chain)

    val trust = rootCACertificates.map { cert -> TrustAnchor(cert, null) }.toSet()
    val pkixParameters = PKIXParameters(trust).apply(customizePKIX)

    val validator = CertPathValidator.getInstance("PKIX")
    validator.validate(certPath, pkixParameters)
}

private fun parseDer(der: List<Base64>): Either<Throwable, JWK> = Either.catch {
    val chain = X509CertChainUtils.parse(der).toNonEmptyListOrNull()
    requireNotNull(chain) { "der must contain no certificates" }
    JWK.parse(chain.head)
}
