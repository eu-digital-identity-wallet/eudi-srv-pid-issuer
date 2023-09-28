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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import java.util.*

private const val PID_DOCTYPE = "eu.europa.ec.eudiw.pid"
val PisMsoMdocScope: Scope = Scope("${PID_DOCTYPE}_mso_mdoc")

val PidMsoMdocV1: MsoMdocMetaData = MsoMdocMetaData(
    docType = pidDocType(1),
    display = listOf(
        CredentialDisplay(
            name = DisplayName("PID", Locale.ENGLISH),
            logo = ImageUrl(
                url = HttpsUrl.of("https://examplestate.com/public/mdl.png")!!,
                alternativeText = "A square figure of a PID",
            ),
        ),
    ),
    msoClaims = buildMap {
        put(
            pidNameSpace(1),
            listOf(
                MsoAttribute(
                    name = "family_name",
                    display = mapOf(Locale.ENGLISH to "Current Family Name"),
                ),
                MsoAttribute(
                    name = "given_name",
                    display = mapOf(Locale.ENGLISH to "Current First Names"),
                ),
                MsoAttribute(
                    name = "birth_date",
                    display = mapOf(Locale.ENGLISH to "Date of Birth"),
                ),
                MsoAttribute(
                    name = "age_over_18",
                    display = mapOf(Locale.ENGLISH to "Adult or minor"),
                ),
                MsoAttribute(
                    name = "age_birth_year",
                ),
                MsoAttribute(
                    name = "unique_id",
                    display = mapOf(Locale.ENGLISH to "Unique Identifier"),
                ),
            ),
        )
    },
    cryptographicSuitesSupported = listOf(
        JWSAlgorithm.ES256,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
    ),
    scope = PisMsoMdocScope,

)

private fun pidDocType(v: Int?): String =
    if (v == null) PID_DOCTYPE
    else "$PID_DOCTYPE.$v"

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)
