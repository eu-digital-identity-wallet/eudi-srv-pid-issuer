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
package eu.europa.ec.eudi.pidissuer.domain.pid

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*

val PisMsoMdocScope: Scope = Scope("${PID_DOCTYPE}_$MSO_MDOC_FORMAT")

val PidMsoMdocV1: MsoMdocMetaData = MsoMdocMetaData(
    docType = pidDocType(1),
    display = pidDisplay,
    msoClaims = mapOf(pidNameSpace(1) to pidAttributes),
    cryptographicSuitesSupported = listOf(
        JWSAlgorithm.ES256K,
    ),
    scope = PisMsoMdocScope,
)

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

fun MsoMdocCredentialRequest.validatePidMsoMdocV1(): Either<String, Unit> = either {
    ensure(docType == PidMsoMdocV1.docType) { "doctype is $docType but was expecting ${PidMsoMdocV1.docType}" }
    claims.forEach {
    }
}
