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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.LocalDate
import kotlin.test.Test

class EncodePidInCborWithMicroServiceTest {

    private val json = Json { prettyPrint = true }

    @Test
    fun `createMsoMdocReq() happy path`() {
        val (pid, pidMetaData) = pidData
        val request = createMsoMdocReq(pid, pidMetaData, holderKey)
        request.also { println(json.encodeToString(it)) }
    }

    private val holderKey: ECKey by lazy {
        ECKeyGenerator(Curve.P_256).keyID("wallet-0").generate()
    }

    private val pidData: Pair<Pid, PidMetaData> by lazy {
        val birthDate = LocalDate.of(1965, 1, 1)

        val pid = Pid(
            familyName = FamilyName("Garcia"),
            givenName = GivenName("javier"),
            birthDate = birthDate,
            ageOver18 = true,
        )
        val pidMetaData = PidMetaData(
            issuanceDate = LocalDate.of(2023, 7, 19),
            expiryDate = LocalDate.of(2023, 8, 19),
            issuingAuthority = IssuingAuthority.AdministrativeAuthority("Some authority"),
            issuingCountry = IsoCountry("FC"),
        )

        pid to pidMetaData
    }
}
