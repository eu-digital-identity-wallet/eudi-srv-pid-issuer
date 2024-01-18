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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import arrow.core.getOrElse
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.pidissuer.WebClients
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import kotlinx.coroutines.runBlocking

private val getMobileDrivingLicenceData: GetMobileDrivingLicenceData by lazy {
    GetMobileDrivingLicenceDataMock()
}

private val encodeMobileDrivingLicenceInCbor: EncodeMobileDrivingLicenceInCbor by lazy {
    EncodeMobileDrivingLicenceInCborWithMicroservice(
        WebClients.Insecure,
        HttpsUrl.unsafe("https://preprod.issuer.eudiw.dev/formatter/cbor"),
    )
}

private val holderKey: ECKey by lazy {
    ECKeyGenerator(Curve.P_256).generate()
}

fun main() {
    runBlocking {
        val context = AuthorizationContext("access-token", nonEmptySetOf(MobileDrivingLicenceV1Scope))
        either {
            val licence = requireNotNull(getMobileDrivingLicenceData(context))
            encodeMobileDrivingLicenceInCbor(licence, holderKey)
        }.getOrElse { throw RuntimeException(it.msg, it.cause) }
    }
}
