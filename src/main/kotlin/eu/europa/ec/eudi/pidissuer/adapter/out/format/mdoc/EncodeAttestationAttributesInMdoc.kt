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
package eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.certificate
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.x509.dropRootCA
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters.X5ChainHeaderPlacement
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAClaimParameters
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAPayloadParameters
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAService
import eu.europa.esig.dss.enumerations.*
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection
import eu.europa.esig.dss.token.DSSPrivateKeyAccessEntry
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import java.security.PrivateKey
import kotlin.io.encoding.Base64
import kotlin.time.Instant
import java.time.Instant as JavaInstant
import java.util.Date as JavaDate

private val base64UrlSafeNoPadding = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

@Suppress("FunctionName")
fun <Attr> EncodeAttestationAttributesInMdoc(
    issuerSigningKey: IssuerSigningKey,
    docType: MsoDocType,
    usage: MdocEAAClaimParameters.(Attr) -> Unit,
): EncodeAttestationAttributes<Attr> =
    object : EncodeAttestationAttributes<Attr> {
        override suspend fun invoke(attestationAttributes: AttestationAttributes<Attr>): JsonElement {
            val (credential, issuedAt, expiresAt, _, deviceKey, statusListToken) = attestationAttributes

            val mso =
                MdocEAAPayloadParameters()
                    .apply {
                        this.docType = docType
                        signed = JavaDate.from(JavaInstant.ofEpochSecond(issuedAt.epochSeconds))
                        validFrom = JavaDate.from(JavaInstant.ofEpochSecond(issuedAt.epochSeconds))
                        validUntil = JavaDate.from(JavaInstant.ofEpochSecond(expiresAt.epochSeconds))
                        expectedUpdate = null
                        if (null != deviceKey) {
                            this.deviceKey = deviceKey.toECKey().toECPublicKey()
                        }
                        if (null != statusListToken) {
                            setStatusList(statusListToken.index.toInt(), statusListToken.statusList.toString())
                        }
                        selectivelyDisclosable().usage(credential)
                    }

            val signatureParameters = signatureParameters(issuedAt)
            val service = MdocEAAService(CommonCertificateVerifier())

            val issuerAuthPayload = service.getDataToBeSigned(mso, signatureParameters)

            val signingKey = issuerSigningKey.toDSSPrivateKeyAccessEntry()
            val signer = SimpleSignatureTokenConnection(signingKey)
            val signature = signer.sign(issuerAuthPayload, signatureParameters.digestAlgorithm, signingKey)

            val issuerAuth = service.signEAA(mso, signatureParameters, signature)

            val issuerSigned = service.createIssuerSigned(issuerAuth, service.getDisclosures(mso))
            val serializedIssuerSigned = issuerSigned.openStream().use { it.readBytes() }
            return JsonPrimitive(base64UrlSafeNoPadding.encode(serializedIssuerSigned))
        }

        private fun signatureParameters(signingDate: Instant): CBAdESSignatureParameters =
            CBAdESSignatureParameters()
                .apply {
                    signatureLevel = SignatureLevel.CB_AdES_BASELINE_B
                    signaturePackaging = SignaturePackaging.ENVELOPING

                    coseStructureType = COSEStructureType.COSE_SIGN1
                    isTagged = false

                    bLevel().signingDate = JavaDate.from(JavaInstant.ofEpochSecond(signingDate.epochSeconds))

                    signingCertificate = CertificateToken(issuerSigningKey.certificate)
                    certificateChain =
                        issuerSigningKey.key
                            .parsedX509CertChain
                            .dropRootCA()
                            .map { CertificateToken(it) }
                    isIncludeCertificateChain = true
                    x5ChainHeaderPlacement = X5ChainHeaderPlacement.unprotectedHeader
                    isIncludeCertificateChainThumbprints = true
                    if (null != issuerSigningKey.key.keyID) {
                        isIncludeKeyIdentifier = true
                        keyIdentifier = issuerSigningKey.key.keyID.encodeToByteArray()
                    } else {
                        isIncludeKeyIdentifier = false
                    }
                    signingCertificateDigestMethod = DigestAlgorithm.SHA256

                    digestAlgorithm =
                        when (issuerSigningKey.key.curve) {
                            Curve.P_256 -> DigestAlgorithm.SHA256
                            Curve.P_384 -> DigestAlgorithm.SHA384
                            Curve.P_521 -> DigestAlgorithm.SHA512
                            else -> error("Unsupported ECKey Curve '${issuerSigningKey.key.curve}'")
                        }
                }
    }

private class SimpleSignatureTokenConnection(
    private val key: DSSPrivateKeyEntry,
) : AbstractSignatureTokenConnection() {
    override fun close() {
        // no-op
    }

    override fun getKeys(): List<DSSPrivateKeyEntry> = listOf(key)
}

private fun IssuerSigningKey.toDSSPrivateKeyAccessEntry(): DSSPrivateKeyAccessEntry =
    object : DSSPrivateKeyAccessEntry {
        override fun getPrivateKey(): PrivateKey = this@toDSSPrivateKeyAccessEntry.key.toECPrivateKey()

        override fun getCertificate(): CertificateToken = CertificateToken(this@toDSSPrivateKeyAccessEntry.certificate)

        override fun getCertificateChain(): Array<CertificateToken> =
            this@toDSSPrivateKeyAccessEntry
                .key
                .parsedX509CertChain
                .dropRootCA()
                .map { CertificateToken(it) }
                .toTypedArray()

        override fun getEncryptionAlgorithm(): EncryptionAlgorithm =
            EncryptionAlgorithm.forKey(this@toDSSPrivateKeyAccessEntry.key.toECPrivateKey())
    }
