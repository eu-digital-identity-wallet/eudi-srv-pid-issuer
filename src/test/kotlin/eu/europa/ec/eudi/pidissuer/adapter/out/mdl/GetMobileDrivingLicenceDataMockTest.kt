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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.utils.ClientStatusConfiguration
import eu.europa.ec.eudi.pidissuer.utils.createAccessTokenValue
import kotlinx.coroutines.test.runTest
import org.springframework.beans.factory.annotation.Autowired
import kotlin.test.Test

@PidIssuerApplicationTest
internal class GetMobileDrivingLicenceDataMockTest {

    @Autowired
    private lateinit var clock: Clock

    @Test
    internal fun `get mDL success`() = runTest {
        val getMobileDrivingLicenceData = GetMobileDrivingLicenceDataMock()
        val clientStatusConfiguration = ClientStatusConfiguration(clock)
        val accessTokenValue = createAccessTokenValue(clientStatusConfiguration)

        getMobileDrivingLicenceData(
            AuthorizationContext(
                "username",
                BearerAccessToken.parse("Bearer $accessTokenValue"),
                nonEmptySetOf(Scope("test")),
            ),
        ).getOrElse { throw RuntimeException(it.msg, it.cause) }
    }
}
