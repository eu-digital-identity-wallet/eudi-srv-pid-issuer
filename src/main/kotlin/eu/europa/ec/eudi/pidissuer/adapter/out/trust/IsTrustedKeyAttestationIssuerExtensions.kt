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
package eu.europa.ec.eudi.pidissuer.adapter.out.trust

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.IsTrustedKeyAttestationIssuer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

fun IsTrustedKeyAttestationIssuer.Companion.usingTrustValidatorService(
    webClient: WebClient,
    service: URI,
): IsTrustedKeyAttestationIssuer = IsTrustedKeyAttestationIssuer { x5c ->
    val body = TrustQueryRequest(x5c, "EU_WUA")
    val configClient = webClient.post().apply {
        uri(service)
        bodyValue(body)
        contentType(MediaType.APPLICATION_JSON)
        accept(MediaType.APPLICATION_JSON)
    }
    configClient.retrieve()
        .awaitBody<TrustResponse>()
        .trusted
}
val IsTrustedKeyAttestationIssuer.Companion.Ignored: IsTrustedKeyAttestationIssuer get() = IsTrustedKeyAttestationIssuer { true }

@Serializable
private data class TrustQueryRequest(
    @Serializable(with = X509CertificateChainSerializer::class)
    val x5c: NonEmptyList<X509Certificate>,
    val case: String,
)

private object X509CertificateSerializer : KSerializer<X509Certificate> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("X509Certificate", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: X509Certificate) {
        val encoded = kotlin.io.encoding.Base64.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT_OPTIONAL).encode(value.encoded)
        encoder.encodeString(encoded)
    }

    override fun deserialize(decoder: Decoder): X509Certificate {
        val cert = decoder.decodeString()
        val decoded = kotlin.io.encoding.Base64.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT_OPTIONAL).decode(cert)
        val cf = CertificateFactory.getInstance("X.509")
        return ByteArrayInputStream(decoded).use { inputStream ->
            cf.generateCertificate(inputStream) as X509Certificate
        }
    }
}
object X509CertificateChainSerializer : KSerializer<NonEmptyList<X509Certificate>> by NonEmptyListSerializer(
    X509CertificateSerializer,
)

@Serializable
private data class TrustResponse(
    @Required val trusted: Boolean,
)
