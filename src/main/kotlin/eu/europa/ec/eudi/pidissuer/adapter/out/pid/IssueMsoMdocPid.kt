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

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.raise.withError
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateJwtProof
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

val PidMsoMdocScope: Scope = Scope("${PID_DOCTYPE}_${MSO_MDOC_FORMAT.value}")

val PidMsoMdocV1: MsoMdocMetaData = MsoMdocMetaData(
    docType = pidDocType(1),
    display = pidDisplay,
    msoClaims = mapOf(pidNameSpace(1) to pidAttributes),
    cryptographicSuitesSupported = nonEmptySetOf(JWSAlgorithm.ES256K),
    scope = PidMsoMdocScope,
)

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

/**
 * Service for issuing PID MsoMdoc credential
 */
class IssueMsoMdocPid(
    private val validateJwtProof: ValidateJwtProof,
    private val getPidData: GetPidData,
    private val encodePidInCbor: EncodePidInCbor,
) : IssueSpecificCredential<JsonElement> {

    override val supportedCredential: CredentialMetaData
        get() = PidMsoMdocV1

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val cbor = encodePidInCbor(pid, pidMetaData, holderPubKey.await())
        CredentialResponse.Issued(JsonPrimitive(cbor))
    }

    context(Raise<IssueCredentialError>)
    private suspend fun holderPubKey(
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): ECKey {
        val key =
            when (val proof = request.unvalidatedProof) {
                is UnvalidatedProof.Jwt ->
                    validateJwtProof(
                        proof,
                        expectedCNonce,
                        supportedCredential.cryptographicSuitesSupported(),
                    ).getOrElse { raise(IssueCredentialError.InvalidProof("Proof is not valid", it)) }

                is UnvalidatedProof.Cwt -> raise(IssueCredentialError.InvalidProof("Supporting only JWT proof"))
            }

        return withError({ _: Throwable -> IssueCredentialError.InvalidProof("Only EC Key is supported") }) {
            when (key) {
                is CredentialKey.DIDUrl -> raise(IssueCredentialError.InvalidProof("DID not supported"))
                is CredentialKey.Jwk -> key.value.toECKey()
                is CredentialKey.X5c -> ECKey.parse(key.certificate)
            }
        }
    }
}
