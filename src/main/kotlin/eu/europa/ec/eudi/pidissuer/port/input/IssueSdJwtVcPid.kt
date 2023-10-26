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
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.domain.pid.PidSdJwtVcV1
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData
import kotlinx.serialization.json.JsonElement

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid(
    private val getPidData: GetPidData,
) : IssueSpecificCredential(PidSdJwtVcV1) {
    context(Raise<Err>) override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> {
        TODO("Not yet implemented")
    }
}
