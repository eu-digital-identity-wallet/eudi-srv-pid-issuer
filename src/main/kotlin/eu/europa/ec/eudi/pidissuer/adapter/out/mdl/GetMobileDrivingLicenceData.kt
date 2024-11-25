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

import arrow.core.Either
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError

/**
 * Gets the data of the Mobile Driving Licence of an authorized user.
 */
fun interface GetMobileDrivingLicenceData {

    /**
     * Gets the data of the Mobile Driving Licence of an authorized user. In case the authorized user
     * has no Driving Licence, null is returned.
     */

    suspend operator fun invoke(context: AuthorizationContext): Either<IssueCredentialError.Unexpected, MobileDrivingLicence?>
}
