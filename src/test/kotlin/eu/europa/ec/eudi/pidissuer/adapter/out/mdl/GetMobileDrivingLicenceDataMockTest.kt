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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import arrow.core.getOrElse
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

internal class GetMobileDrivingLicenceDataMockTest {

    @Test
    internal fun `get mDL success`() = runTest {
        val getMobileDrivingLicenceData = GetMobileDrivingLicenceDataMock()
        either {
            getMobileDrivingLicenceData(
                AuthorizationContext("username", BearerAccessToken.parse("Bearer access-token"), nonEmptySetOf(Scope("test"))),
            )
        }.getOrElse { throw RuntimeException(it.msg, it.cause) }
    }
}
