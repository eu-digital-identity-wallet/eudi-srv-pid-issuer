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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.Either
import arrow.core.NonEmptySet
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.result
import arrow.core.toNonEmptySetOrNone
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer.CredentialsOfferTO.GrantsTO.AuthorizationCodeTO
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.glxn.qrgen.core.image.ImageType
import net.glxn.qrgen.javase.QRCode
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

/**
 * A generated Credentials Offer.
 *
 * Contains the [Credentials Offer URI][uri] and a [QR Code][qrCode] in PNG format.
 */
data class GeneratedCredentialsOffer(
    val uri: URI,
    val qrCode: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GeneratedCredentialsOffer

        if (uri != other.uri) return false
        if (!qrCode.contentEquals(other.qrCode)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = uri.hashCode()
        result = 31 * result + qrCode.contentHashCode()
        return result
    }

    companion object
}

/**
 * Errors that might be returned by [CreateCredentialsOffer].
 */
sealed interface CreateCredentialsOfferError {

    /**
     * No Credentials Unique Ids have been provided.
     */
    data object MissingCredentialUniqueIds : CreateCredentialsOfferError

    /**
     * The provided Credential Unique Ids are not valid.
     */
    data object InvalidCredentialUniqueIds : CreateCredentialsOfferError

    /**
     * An unexpected error occurred.
     */
    data class Unexpected(val cause: Throwable) : CreateCredentialsOfferError
}

/**
 * Generates a Credential Offer and a QR Code in PNG format.
 */
class CreateCredentialsOffer(
    private val metadata: CredentialIssuerMetaData,
    private val credentialsOfferUri: URI,
) {
    operator fun invoke(maybeCredentials: Set<CredentialUniqueId>): Either<CreateCredentialsOfferError, GeneratedCredentialsOffer> =
        either {
            val credentials = maybeCredentials.toNonEmptySetOrNone().getOrElse { raise(MissingCredentialUniqueIds) }
            val supportedCredentials = metadata.credentialsSupported.map(CredentialMetaData::id)
            if (!supportedCredentials.containsAll(credentials)) {
                raise(InvalidCredentialUniqueIds)
            }
            val credentialsOffer = CredentialsOfferTO(metadata.id, credentials, metadata.authorizationServers)
            GeneratedCredentialsOffer(credentialsOfferUri, credentialsOffer).getOrElse { raise(Unexpected(it)) }
        }

    companion object {

        /**
         * Creates a new [GeneratedCredentialsOffer].
         *
         * Generate a new [QRCode] using a [credentialsOfferUri] that contains the data of the [credentialsOffer].
         */
        private operator fun GeneratedCredentialsOffer.Companion.invoke(
            credentialsOfferUri: URI,
            credentialsOffer: CredentialsOfferTO,
        ): Result<GeneratedCredentialsOffer> = result {
            val generatedCredentialsOfferUri = UriComponentsBuilder.fromUri(credentialsOfferUri)
                .queryParam("credential_offer", Json.encodeToString(credentialsOffer))
                .build()
                .toUri()
            val generatedQrCode = QRCode.from(generatedCredentialsOfferUri.toString())
                .to(ImageType.PNG)
                .withSize(300, 300)
                .withCharset(Charsets.UTF_8.name())
                .withErrorCorrection(ErrorCorrectionLevel.H)
                .stream()
                .toByteArray()

            GeneratedCredentialsOffer(generatedCredentialsOfferUri, generatedQrCode)
        }
    }

    /**
     * A Credentials Offer using Authorization Code Grant as per
     * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1).
     */
    @Serializable
    private data class CredentialsOfferTO(
        @SerialName("credential_issuer") val credentialIssuer: String,
        @SerialName("credentials") val credentials: Set<String>,
        @SerialName("grants") val grants: GrantsTO? = null,
    ) {
        companion object {

            /**
             * Creates a new [CredentialsOfferTO] for the provided [credentialIssuerId], [credentials] and [authorizationServers].
             * When more than one Authorization Servers are provided, only the first one is included in the resulting
             * [CredentialsOfferTO] as per
             * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1-4.1.2.2).
             */
            operator fun invoke(
                credentialIssuerId: CredentialIssuerId,
                credentials: NonEmptySet<CredentialUniqueId>,
                authorizationServers: List<HttpsUrl>,
            ): CredentialsOfferTO =
                CredentialsOfferTO(
                    credentialIssuerId.externalForm,
                    credentials.map { it.value }.toSet(),
                    GrantsTO(
                        AuthorizationCodeTO(
                            authorizationServers
                                .takeIf { it.size > 1 }
                                ?.first()
                                ?.externalForm,
                        ),
                    ),
                )
        }

        @Serializable
        data class GrantsTO(
            @SerialName("authorization_code") val authorizationCode: AuthorizationCodeTO,
        ) {
            @Serializable
            data class AuthorizationCodeTO(
                @SerialName("authorization_server") val authorizationServer: String? = null,
            )
        }
    }
}
