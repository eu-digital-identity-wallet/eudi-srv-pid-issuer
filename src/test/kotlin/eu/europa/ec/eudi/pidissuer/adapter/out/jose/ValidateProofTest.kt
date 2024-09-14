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

import arrow.core.raise.either
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@OptIn(ExperimentalCoroutinesApi::class)
class ValidateProofTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val validateProof = ValidateProof(issuer)
    private val clock = Clock.systemDefaultZone()

    @Test
    internal fun `fails with unsupported proof type`() = runTest {
        val nonce = CNonce("token", "nonce", clock.instant(), 5.minutes.toJavaDuration())
        val proof = UnvalidatedProof.LdpVp("foo")
        val result = either { validateProof(proof, nonce, PidMsoMdocV1) }
        assert(result.isLeft())
        assertIs<IssueCredentialError.InvalidProof>(result.leftOrNull())
    }
}
