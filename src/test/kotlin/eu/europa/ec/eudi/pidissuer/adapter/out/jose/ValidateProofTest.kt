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
import arrow.core.nonEmptySetOf
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestationRequirement
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class ValidateProofTest {

    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.System
    private val verifyKeyAttestation = VerifyKeyAttestation(
        verifyNonce = { _, _ ->
            fail("VerifyCNonce should not have been invoked")
        },
    )
    private val validateProofs = ValidateProofs(
        validateJwtProof = ValidateJwtProof(issuer, verifyKeyAttestation),
        validateAttestationProof = ValidateAttestationProof(verifyKeyAttestation),
        verifyNonce = { _, _ ->
            fail("VerifyCNonce should not have been invoked")
        },
        extractJwkFromCredentialKey = { _ ->
            fail("ExtractJwkFromCredentialKey should not have been invoked.")
        },
    )

    @Test
    internal fun `fails with unsupported proof type`() = runTest {
        val proof = UnvalidatedProof.DiVp("foo")

        val result =
            validateProofs(
                nonEmptyListOf(proof),
                pidMsoMdocV1(
                    nonEmptySetOf(JWSAlgorithm.ES256),
                    KeyAttestationRequirement.NotRequired,
                ),
                clock.now(),
            )

        assert(result.isLeft())

        val error = assertIs<IssueCredentialError.InvalidProof>(result.leftOrNull())
        assertEquals("Supporting only JWT proof", error.msg)
        assertNull(error.cause)
    }
}
