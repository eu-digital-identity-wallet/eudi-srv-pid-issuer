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
package eu.europa.ec.eudi.pidissuer.adapter.out.status

import arrow.core.toNonEmptyListOrThrow
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedIssuer
import eu.europa.ec.eudi.pidissuer.port.out.trust.TrustResult
import eu.europa.ec.eudi.pidissuer.port.out.trust.VerificationContext
import eu.europa.ec.eudi.statium.VerifyStatusListTokenJwtSignature

/**
 * A [VerifyStatusListTokenJwtSignature] that verifies the JWS signature of a status list token
 * using the certificate chain from the JWT's x5c header, and then checks whether the issuer
 * is trusted using the provided [isTrustedIssuer] service.
 */
fun VerifyStatusListTokenJwtSignature.Companion.usingTrust(
    isTrustedIssuer: IsTrustedIssuer,
    verificationContext: VerificationContext,
): VerifyStatusListTokenJwtSignature =
    VerifyStatusListTokenJwtSignature { statusListToken, _ ->
        runCatching {
            val signedJwt = SignedJWT.parse(statusListToken)

            val x5c = signedJwt.header.x509CertChain
            require(!x5c.isNullOrEmpty()) { "Status list token must contain a valid certificate chain" }

            val chain =
                x5c.map { certificate ->
                    X509CertUtils.parseWithException(certificate.decode())
                }
            val publicKey = chain.first().publicKey

            val verifier = DefaultJWSVerifierFactory().createJWSVerifier(signedJwt.header, publicKey)
            check(signedJwt.verify(verifier)) {
                "Status list token JWT signature is invalid"
            }

            // Check that the issuer is trusted
            val trustResult = isTrustedIssuer(chain.toNonEmptyListOrThrow(), verificationContext)
            check(trustResult is TrustResult.IsTrusted) {
                "Status list token issuer is not trusted"
            }
        }
    }
