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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*

val PisSdjwtVcScope: Scope = Scope("${PID_DOCTYPE}_${SJ_JWT_VC_FORMAT}")

val PidSdJwtVcV1: SdJwtVcMetaData = SdJwtVcMetaData(
    type = SdJwtVcType(pidDocType(1)),
    display = pidDisplay,
    claims = pidAttributes,
    cryptographicBindingMethodsSupported = listOf(
        CryptographicBindingMethod.Jwk,
    ),
    cryptographicSuitesSupported = listOf(
        JWSAlgorithm.ES256K,
    ),
    scope = PisSdjwtVcScope,
)
