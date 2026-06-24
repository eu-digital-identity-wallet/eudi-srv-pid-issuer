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
package eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.EncodeAttributesInSdJwtVcLogging.logDebug
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.x509.dropRootCA
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.asJwsJsonObject
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObject
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory

enum class SdJwtVcSerialization {
    Compact,
    JwsJson,
}

fun <Attr> encodeAttestationAttributesInSdJwtVc(
    sdJwtVcSerialization: SdJwtVcSerialization = SdJwtVcSerialization.Compact,
    digestsHashAlgorithm: HashAlgorithm = HashAlgorithm.SHA_256,
    issuerSigningKey: IssuerSigningKey,
    vct: SdJwtVcType,
    issuer: CredentialIssuerId? = null,
    build: SdJwtObjectBuilder.(Attr) -> Unit,
): EncodeAttestationAttributes<Attr> =
    EncodeAttestationAttributesInSdJwtVc(
        digestsHashAlgorithm,
        sdJwtVcSerialization,
        issuerSigningKey,
        vct,
        issuer,
        build,
    )

private class EncodeAttestationAttributesInSdJwtVc<in Attr>(
    private val digestsHashAlgorithm: HashAlgorithm,
    private val sdJwtVcSerialization: SdJwtVcSerialization,
    private val issuerSigningKey: IssuerSigningKey,
    private val vct: SdJwtVcType,
    private val issuer: CredentialIssuerId? = null,
    private val build: SdJwtObjectBuilder.(Attr) -> Unit,
) : EncodeAttestationAttributes<Attr> {
    override suspend fun invoke(attestationAttributes: AttestationAttributes<Attr>): JsonElement {
        val (attributes, issuedAt, expiresAt, notBefore, deviceKey, status, jwtId) = attestationAttributes
        val spec =
            sdJwt {
                claim(SdJwtVcSpec.VCT, vct.value)
                claim(RFC7519.ISSUED_AT, issuedAt.epochSeconds)
                claim(RFC7519.EXPIRATION_TIME, expiresAt.epochSeconds)
                issuer?.let { claim(RFC7519.ISSUER, it.externalForm) }
                notBefore?.let { claim(RFC7519.NOT_BEFORE, it.epochSeconds) }
                jwtId?.let { claim(RFC7519.JWT_ID, it) }
                deviceKey?.let { cnf(it) }
                status?.let {
                    objClaim("status") {
                        objClaim("status_list") {
                            claim("idx", it.index.toInt())
                            claim("uri", it.statusList.toString())
                        }
                    }
                }
                build(attributes)
            }
        return enode(spec)
    }

    private suspend fun enode(spec: SdJwtObject): JsonElement =
        context(issuerSigningKey, digestsHashAlgorithm, sdJwtVcSerialization, NimbusSdJwtOps) {
            val issuer = sdJwtVcIssuer(digestsHashAlgorithm)
            val sdJwt = issuer.issue(spec).getOrThrow().also { it.logDebug() }
            when (sdJwtVcSerialization) {
                SdJwtVcSerialization.Compact -> JsonPrimitive(sdJwt.serialize())
                SdJwtVcSerialization.JwsJson -> sdJwt.asJwsJsonObject(JwsSerializationOption.Flattened)
            }
        }
}

context(issuerSigningKey: IssuerSigningKey)
private fun sdJwtVcIssuer(digestsHashAlgorithm: HashAlgorithm): SdJwtIssuer<SignedJWT> {
    val factory = SdJwtFactory(digestsHashAlgorithm)
    val signer = ECDSASigner(issuerSigningKey.key)
    val x5c =
        issuerSigningKey.key.parsedX509CertChain
            .dropRootCA()
            .map { Base64.encode(it.encoded) }
    return NimbusSdJwtOps.issuer(factory, signer, issuerSigningKey.signingAlgorithm) {
        type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
        keyID(issuerSigningKey.key.keyID)
        x509CertChain(x5c)
    }
}

private object EncodeAttributesInSdJwtVcLogging {
    private val json = Json { prettyPrint = true }
    private val log = LoggerFactory.getLogger(EncodeAttributesInSdJwtVcLogging::class.java)

    private fun JsonElement.pretty(): String = json.encodeToString(this)

    fun SdJwt<SignedJWT>.logDebug() {
        log.debug(prettyPrint())
    }

    fun SdJwt<SignedJWT>.prettyPrint(): String {
        var str = "\nSD-JWT with ${disclosures.size} disclosures\n"
        disclosures.forEach { d ->
            val kind =
                when (d) {
                    is Disclosure.ArrayElement -> "\t - ArrayEntry ${d.claim().value().pretty()}"
                    is Disclosure.ObjectProperty -> "\t - ObjectProperty ${d.claim().first} = ${d.claim().second}"
                }
            str += kind + "\n"
        }
        str += "SD-JWT payload\n"
        str +=
            json.parseToJsonElement(jwt.jwtClaimsSet.toString()).run {
                json.encodeToString(this)
            }
        return str
    }
}
