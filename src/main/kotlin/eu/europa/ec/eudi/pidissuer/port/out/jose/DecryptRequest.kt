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
package eu.europa.ec.eudi.pidissuer.port.out.jose

import arrow.core.raise.Raise
import arrow.core.raise.context.raise
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.decryptWithNimbus
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequestEncryption
import eu.europa.ec.eudi.pidissuer.port.out.jose.RequestEncryptionError.RequestEncryptionNotSupported
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.serializer

context(
    _: Raise<RequestEncryptionError>,
    _: CredentialIssuerMetaData,
)
suspend inline fun <reified T> decryptCredentialRequest(jwt: String): T = decryptCredentialRequest(serializer(), jwt)

context(
    _: Raise<RequestEncryptionError>,
    _: CredentialIssuerMetaData,
)
suspend fun <T> decryptCredentialRequest(
    deserializer: DeserializationStrategy<T>,
    jwt: String,
): T = context(encryptionParameters(), deserializer) { decryptWithNimbus(jwt) }

context(
    _: Raise<RequestEncryptionError>,
    credentialIssuerMetadata: CredentialIssuerMetaData,
)
private fun encryptionParameters() =
    when (val requestEncryption = credentialIssuerMetadata.credentialRequestEncryption) {
        is CredentialRequestEncryption.Optional -> requestEncryption.parameters
        is CredentialRequestEncryption.Required -> requestEncryption.parameters
        is CredentialRequestEncryption.NotSupported -> raise(RequestEncryptionNotSupported)
    }
