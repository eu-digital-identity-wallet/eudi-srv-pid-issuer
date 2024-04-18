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

import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import arrow.core.raise.result
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
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
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import foundation.identity.did.DIDURL
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAPublicKey
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit

context (Raise<IssueCredentialError.InvalidProof>)
fun validateJwtProof(
    credentialIssuerId: CredentialIssuerId,
    unvalidatedProof: UnvalidatedProof.Jwt,
    expectedCNonce: CNonce,
    credentialConfiguration: CredentialConfiguration,
): CredentialKey {
    val proofTypes = credentialConfiguration.proofTypesSupported
        .filterIsInstance<ProofType.Jwt>()
        .toNonEmptySetOrNull()
    ensureNotNull(proofTypes) {
        IssueCredentialError.InvalidProof("credential configuration '${credentialConfiguration.id.value}' doesn't support 'jwt' proofs")
    }

    val supportedAlgorithms = proofTypes.flatMap { it.signingAlgorithmsSupported }.toNonEmptySet()
    return validateJwtProof(credentialIssuerId, unvalidatedProof, expectedCNonce, supportedAlgorithms)
}

context (Raise<IssueCredentialError.InvalidProof>)
fun validateJwtProof(
    credentialIssuerId: CredentialIssuerId,
    unvalidatedProof: UnvalidatedProof.Jwt,
    expectedCNonce: CNonce,
    supportedAlgorithms: NonEmptySet<JWSAlgorithm>,
): CredentialKey = result {
    val signedJwt = SignedJWT.parse(unvalidatedProof.jwt)
    val (algorithm, credentialKey) = algorithmAndCredentialKey(signedJwt.header, supportedAlgorithms)
    val keySelector = keySelector(credentialKey, algorithm)
    val processor = processor(expectedCNonce, credentialIssuerId, keySelector)
    processor.process(signedJwt, null)
    credentialKey
}.getOrElse { raise(IssueCredentialError.InvalidProof("Invalid proof JWT", it)) }

private fun algorithmAndCredentialKey(
    header: JWSHeader,
    supported: NonEmptySet<JWSAlgorithm>,
): Pair<JWSAlgorithm, CredentialKey> {
    val algorithm = header.algorithm
        .takeIf(JWSAlgorithm.Family.SIGNATURE::contains)
        ?.takeIf(supported::contains)
        ?: error("signing algorithm '${header.algorithm.name}' is not supported")

    val kid = header.keyID
    val jwk = header.jwk
    val x5c = header.x509CertChain

    val key = when {
        kid != null && jwk == null && x5c.isNullOrEmpty() -> {
            val url = DIDURL.fromString(kid)
            CredentialKey.DIDUrl(url, resolveDidUrl(url).getOrThrow())
        }
        kid == null && jwk != null && x5c.isNullOrEmpty() -> CredentialKey.Jwk(jwk)
        kid == null && jwk == null && !x5c.isNullOrEmpty() -> CredentialKey.X5c.parseDer(x5c).getOrThrow()

        else -> error("a public key must be provided in one of 'kid', 'jwk', or 'x5c'")
    }.apply { ensureCompatibleWith(algorithm) }

    return (algorithm to key)
}

private fun CredentialKey.ensureCompatibleWith(algorithm: JWSAlgorithm) {
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

private fun keySelector(
    credentialKey: CredentialKey,
    algorithm: JWSAlgorithm,
): JWSKeySelector<SecurityContext> {
    fun <C : SecurityContext> JWK.keySelector(algorithm: JWSAlgorithm): SingleKeyJWSKeySelector<C> =
        when (this) {
            is AsymmetricJWK -> SingleKeyJWSKeySelector(algorithm, toPublicKey())
            else -> TODO("CredentialKey.Jwk with non AsymmetricJWK is not yet supported")
        }

    return when (credentialKey) {
        is CredentialKey.DIDUrl -> credentialKey.jwk.keySelector(algorithm)
        is CredentialKey.Jwk -> credentialKey.value.keySelector(algorithm)
        is CredentialKey.X5c -> SingleKeyJWSKeySelector(algorithm, credentialKey.certificate.publicKey)
    }
}

private val expectedType = JOSEObjectType("openid4vci-proof+jwt")
private val maxSkew = 30.seconds

private fun processor(
    expected: CNonce,
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
                    JWTClaimsSet.Builder()
                        .claim("nonce", expected.nonce)
                        .build(),
                    setOf("iat", "nonce"),
                ).apply {
                    maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                }
        }
