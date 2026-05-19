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
package eu.europa.ec.eudi.pidissuer.utils

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.TS3
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private val accessTokenSigner = ECDSASigner(ECKeyGenerator(Curve.P_256).generate())

fun createAccessTokenValue(includeClientStatus: Boolean = true, expiresAt: Instant = (Clock.System.now() + 32.days)): String {
    val jwtClaimSet = JWTClaimsSet.Builder().apply {
        if (includeClientStatus) {
            claim(
                TS3.CLIENT_STATUS,
                JSONObjectUtils.parse(
                    """
                           {
                              "status": {
                                "status_list": {
                                  "idx": 1337,
                                  "uri": "https://revocation_url/wia-statuslists/42"
                                }
                              },
                              "exp": ${expiresAt.epochSeconds}
                            }
                    """.trimIndent(),
                ),
            )
        }
    }.build()

    return SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256).build(),
        jwtClaimSet,
    ).apply { sign(accessTokenSigner) }.serialize()
}
