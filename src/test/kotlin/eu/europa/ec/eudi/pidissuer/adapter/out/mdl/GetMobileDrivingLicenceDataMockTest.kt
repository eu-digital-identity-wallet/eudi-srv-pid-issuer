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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import arrow.core.getOrElse
import arrow.core.nonEmptySetOf
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.TS3
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

internal class GetMobileDrivingLicenceDataMockTest {

    @Test
    internal fun `get mDL success`() = runTest {
        val getMobileDrivingLicenceData = GetMobileDrivingLicenceDataMock()

        val signer = ECDSASigner(ECKeyGenerator(Curve.P_256).generate())

        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).build(),
            JWTClaimsSet.Builder()
                .claim(
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
                              "exp": 1303497780
                            }
                        """.trimIndent(),
                    ),
                )
                .build(),
        ).apply { sign(signer) }

        getMobileDrivingLicenceData(
            AuthorizationContext(
                "username",
                BearerAccessToken.parse("Bearer ${signedJwt.serialize()}"),
                nonEmptySetOf(Scope("test")),
            ),
        ).getOrElse { throw RuntimeException(it.msg, it.cause) }
    }
}
