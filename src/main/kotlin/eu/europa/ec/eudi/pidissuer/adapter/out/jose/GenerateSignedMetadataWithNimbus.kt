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

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.util.JSONObjectUtils
import eu.europa.ec.eudi.pidissuer.domain.Clock
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.OpenId4VciSpec
import eu.europa.ec.eudi.pidissuer.port.out.jose.GenerateSignedMetadata
import kotlinx.serialization.json.*

/**
 * Key used to sign metadata.
 */
data class MetadataSigningKey(
    val key: JWK,
    val issuer: String,
) {
    init {
        require(key is AsymmetricJWK) { "only asymmetric keys are supported" }
        require(key.isPrivate) { "a private key is required for signing metadata" }
        require(issuer.isNotBlank()) { "issuer cannot be blank" }
    }

    val signingAlgorithm: JWSAlgorithm
        get() = when (key) {
            is ECKey -> when (val curve = key.curve) {
                Curve.P_256 -> JWSAlgorithm.ES256
                Curve.P_384 -> JWSAlgorithm.ES384
                Curve.P_521 -> JWSAlgorithm.ES512
                else -> error("unsupported curve '$curve' for ECKey")
            }
            is RSAKey -> JWSAlgorithm.RS256
            is OctetKeyPair -> when (val curve = key.curve) {
                Curve.Ed25519 -> JWSAlgorithm.Ed25519
                else -> error("unsupported curve '$curve' for OctetKeyPair")
            }
            else -> error("unsupported key type '$javaClass'")
        }

    val jwsHeader: JWSHeader
        get() = JWSHeader.Builder(signingAlgorithm)
            .apply {
                type(JOSEObjectType(OpenId4VciSpec.SIGNED_METADATA_JWT_TYPE))
                val publicJwk = key.toPublicJWK()
                if (null != publicJwk.x509CertChain) {
                    x509CertChain(publicJwk.x509CertChain)
                } else {
                    jwk(publicJwk)
                }
            }
            .build()

    val jwsSigner: JWSSigner
        get() = when (key) {
            is ECKey -> ECDSASigner(key)
            is RSAKey -> RSASSASigner(key)
            is OctetKeyPair -> Ed25519Signer(key)
            else -> error("unsupported key type '$javaClass'")
        }
}

/**
 * Nimbus implementation of [GenerateSignedMetadata].
 */
internal class GenerateSignedMetadataWithNimbus(
    private val clock: Clock,
    private val credentialIssuerId: CredentialIssuerId,
    private val signingKey: MetadataSigningKey,
) : GenerateSignedMetadata {
    override fun invoke(metadata: JsonObject): String {
        val payload = (metadata - "signed_metadata").buildUpon {
            put("iat", clock.now().epochSeconds)
            put("iss", signingKey.issuer)
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
