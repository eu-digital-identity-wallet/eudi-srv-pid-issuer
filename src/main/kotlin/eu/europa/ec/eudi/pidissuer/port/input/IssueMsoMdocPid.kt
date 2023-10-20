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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.withError
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialRequestFormat
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocMetaData
import eu.europa.ec.eudi.pidissuer.domain.validate
import eu.europa.ec.eudi.pidissuer.port.out.pid.GetPidData

/**
 * Service for issuing PID MsoMdoc credential
 */
class IssueMsoMdocPid(private val getPidData: GetPidData, private val pidMeta: MsoMdocMetaData) {
    suspend operator fun invoke(request: CredentialRequest): Either<IssueCredentialError, String> = either {
        val requestedFormat = isPidMsoMdocRequest(request).bind()

        TODO()
    }

    private fun isPidMsoMdocRequest(request: CredentialRequest): Either<IssueCredentialError, MsoMdocCredentialRequestFormat> =
        either {
            val requestFormat = request.format
            withError({ error -> IssueCredentialError.InvalidFormat(error) }) {
                ensure(requestFormat is MsoMdocCredentialRequestFormat) { "Unexpected format" }
                requestFormat.validate(pidMeta).bind()
                requestFormat
            }
        }
}
