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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.domain.pid.Pid
import eu.europa.ec.eudi.pidissuer.domain.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Service for issuing PID MsoMdoc credential
 */
class IssueMsoMdocPid(
    private val getPidData: GetPidData,
) : IssueSpecificCredential {

    override val supportedCredential: CredentialMetaData
        get() = PidMsoMdocV1

    context(Raise<Err>) override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        val pidDataDeffered = async { getPidData(authorizationContext.accessToken) }
        val pidData = pidDataDeffered.await()
        ensureNotNull(pidData) { Err.Unexpected("Cannot obtain PID data") }
        val cbor = cbor(pidData)
        CredentialResponse.Issued(cbor.toJson())
    }
}

private fun cbor(pid: Pid): MsoMdocIssuedCredential {
    @Serializable
    data class DummyPidCbor(
        val familyName: String,
        val givenName: String,
    )

    val dummy = DummyPidCbor(
        pid.familyName.value,
        pid.givenName.value,

    )
    val cbor = Cbor.encodeToByteArray(dummy)
    return MsoMdocIssuedCredential(cbor)
}

@OptIn(ExperimentalEncodingApi::class)
private fun MsoMdocIssuedCredential.toJson(): JsonPrimitive = JsonPrimitive(Base64.UrlSafe.encode(credential))
