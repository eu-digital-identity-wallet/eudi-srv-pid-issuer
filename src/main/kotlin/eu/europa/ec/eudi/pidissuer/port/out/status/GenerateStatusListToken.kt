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
package eu.europa.ec.eudi.pidissuer.port.out.status

import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import java.time.ZonedDateTime

fun interface GenerateStatusListToken {

    /**
     * Generates a new [StatusListToken].
     *
     * @param type the type of the VC for which a Status List Token is generated.
     * e.g. 'urn:eu.europa.ec.eudi:pid:', or 'eu.europa.ec.eudi.pid.1', or 'org.iso.18013.5.1.mDL'
     * @param expiration expiration date of the issued VC
     */
    suspend operator fun invoke(type: String, expiration: ZonedDateTime): Result<StatusListToken>
}
