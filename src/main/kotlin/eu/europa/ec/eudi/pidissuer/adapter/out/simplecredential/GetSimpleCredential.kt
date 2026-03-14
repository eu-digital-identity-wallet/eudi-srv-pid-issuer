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
package eu.europa.ec.eudi.pidissuer.adapter.out.simplecredential

import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetPidData
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext

fun interface GetSimpleCredential {
    suspend operator fun invoke(context: AuthorizationContext): SimpleCredential

    companion object {
        fun mock(clock: Clock, getPidData: GetPidData): GetSimpleCredential =
            GetMockSimpleCredential(clock, getPidData)
    }
}

private class GetMockSimpleCredential(
    private val clock: Clock,
    private val getPidData: GetPidData,
) : GetSimpleCredential {
    override suspend fun invoke(context: AuthorizationContext): SimpleCredential {
        val now = clock.now()
        val pid = checkNotNull(getPidData(context.username)?.first)
        return SimpleCredential(
            familyName = SimpleFamilyName(pid.familyName.value),
            givenName = SimpleGivenName(pid.givenName.value),
            email = SimpleEmail("${pid.givenName.value.lowercase()}.${pid.familyName.value.lowercase()}@example.com"),
            dateOfBirth = SimpleDateOfBirth(pid.birthDate.toString()),
            issuanceDate = now,
        )
    }
}
