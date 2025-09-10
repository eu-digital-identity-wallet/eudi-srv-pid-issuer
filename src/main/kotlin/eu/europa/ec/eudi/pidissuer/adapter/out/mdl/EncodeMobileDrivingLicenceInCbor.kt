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
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import kotlin.time.Instant

/**
 * Encodes a Mobile Driving Licence in CBOR format.
 */
fun interface EncodeMobileDrivingLicenceInCbor {

    suspend operator fun invoke(
        licence: MobileDrivingLicence,
        holderKey: ECKey,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError.Unexpected, String>
}
