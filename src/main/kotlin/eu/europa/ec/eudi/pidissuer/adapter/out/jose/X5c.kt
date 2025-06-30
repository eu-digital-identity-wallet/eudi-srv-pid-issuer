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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import arrow.core.Either
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertChainUtils
import eu.europa.ec.eudi.pidissuer.domain.CredentialKey

fun CredentialKey.X5c.Companion.parseDer(der: List<Base64>): Either<Throwable, CredentialKey.X5c> = Either.catch {
    val chain = X509CertChainUtils.parse(der).toNonEmptyListOrNull()
    requireNotNull(chain) { "der must contain no certificates" }
    CredentialKey.X5c(chain)
}
