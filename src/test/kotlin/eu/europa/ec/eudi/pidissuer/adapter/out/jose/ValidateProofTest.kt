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

import arrow.core.nonEmptyListOf
import arrow.core.raise.either
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import kotlinx.coroutines.test.runTest
import java.time.Clock
import kotlin.test.*

class ValidateProofTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.systemDefaultZone()
    private val validateProofs = ValidateProofs(ValidateJwtProof(issuer) { TODO() }, clock) { _ -> TODO() }

    @Test
    internal fun `fails with unsupported proof type`() = runTest {
        val proof = UnvalidatedProof.LdpVp("foo")

        val result = either { validateProofs(nonEmptyListOf(proof), PidMsoMdocV1) }
        assert(result.isLeft())

        val error = assertIs<IssueCredentialError.InvalidProof>(result.leftOrNull())
        assertEquals("Supporting only JWT proof", error.msg)
        assertNull(error.cause)
    }
}
