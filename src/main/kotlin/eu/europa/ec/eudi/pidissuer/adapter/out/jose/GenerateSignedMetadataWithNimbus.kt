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

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.JSONObjectUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.port.out.jose.GenerateSignedMetadata
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.time.Clock

/**
 * Nimbus implementation of [GenerateSignedMetadata].
 */
internal class GenerateSignedMetadataWithNimbus(
    private val clock: Clock,
    private val credentialIssuerId: CredentialIssuerId,
    private val signingKey: IssuerSigningKey,
) : GenerateSignedMetadata {

    override fun invoke(metadata: JsonObject): String {
        val payload = (metadata - "signed_metadata").buildUpon {
            put("iat", clock.instant().epochSecond)
            put("iss", credentialIssuerId.externalForm)
            put("sub", credentialIssuerId.externalForm)
        }.toPayload()

        val signedMetadata = JWSObject(signingKey.jwsHeader, payload)
            .apply { sign(signingKey.jwsSigner) }

        return signedMetadata.serialize()
    }
}

private fun Map<String, JsonElement>.buildUpon(builder: JsonObjectBuilder.() -> Unit): JsonObject =
    buildJsonObject {
        entries.forEach { (key, value) -> put(key, value) }
        builder()
    }

private fun JsonObject.toPayload(): Payload = Payload(JSONObjectUtils.parse(Json.encodeToString(this)))

private val IssuerSigningKey.jwsHeader: JWSHeader
    get() = JWSHeader.Builder(signingAlgorithm)
        .jwk(key.toPublicJWK())
        .keyID(key.keyID)
        .x509CertChain(key.x509CertChain)
        .build()

private val IssuerSigningKey.jwsSigner: JWSSigner
    get() = ECDSASigner(key)
