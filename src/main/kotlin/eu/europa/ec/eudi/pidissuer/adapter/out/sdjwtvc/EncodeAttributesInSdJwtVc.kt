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
package eu.europa.ec.eudi.pidissuer.adapter.out.sdjwtvc

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.sdjwtvc.EncodeAttributesInSdJwtVcLogging.logDebug
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.x509.dropRootCA
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
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
import kotlin.time.Instant

data class AttestedClaims<out Data>(
    val attributes: Data,
    val deviceKey: JWK? = null,
    val statusListToken: StatusListToken? = null,
    val common: Common,
) {
    data class Common(
        val issuedAt: Instant? = null,
        val expiresAt: Instant? = null,
        val notBefore: Instant? = null,
    )

    companion object {
        fun <Data> partial(comon: Common): (Data, JWK?, StatusListToken?) -> AttestedClaims<Data> =
            { attributes, deviceKey, statusListToken ->
                AttestedClaims(attributes, deviceKey, statusListToken, comon)
            }
    }
}

fun interface EncodeAttributesInSdJwtVc<in Data> {
    enum class Option {
        Compact,
        JwsJson,
    }

    suspend operator fun invoke(data: Data): JsonElement

    companion object {
        operator fun <D> invoke(
            option: Option = Option.Compact,
            digestsHashAlgorithm: HashAlgorithm = HashAlgorithm.SHA_256,
            issuerSigningKey: IssuerSigningKey,
            vct: SdJwtVcType,
            issuer: CredentialIssuerId? = null,
            build: SdJwtObjectBuilder.(D) -> Unit,
        ): EncodeAttributesInSdJwtVc<AttestedClaims<D>> =
            EncodeSdJwtVcSpec(digestsHashAlgorithm, option, issuerSigningKey)
                .contraMap { (attributes, deviceKey, statusListToken, common) ->
                    val (issuedAt, expiresAt, notBefore) = common
                    sdJwt {
                        claim(SdJwtVcSpec.VCT, vct.value)
                        issuer?.let { claim(RFC7519.ISSUER, it.externalForm) }
                        issuedAt?.let { claim(RFC7519.ISSUED_AT, it.epochSeconds) }
                        notBefore?.let { claim(RFC7519.NOT_BEFORE, it.epochSeconds) }
                        expiresAt?.let { claim(RFC7519.EXPIRATION_TIME, it.epochSeconds) }
                        deviceKey?.let { cnf(it) }
                        statusListToken?.let {
                            objClaim("status") {
                                objClaim("status_list") {
                                    claim("idx", it.index.toInt())
                                    claim("uri", it.statusList.toString())
                                }
                            }
                        }
                        build(attributes)
                    }
                }
    }
}

private fun <D, D1> EncodeAttributesInSdJwtVc<D>.contraMap(f: (D1) -> D): EncodeAttributesInSdJwtVc<D1> =
    EncodeAttributesInSdJwtVcContraMap(this, f)

private class EncodeAttributesInSdJwtVcContraMap<D, D1>(
    private val delegate: EncodeAttributesInSdJwtVc<D1>,
    private val f: (D) -> D1,
) : EncodeAttributesInSdJwtVc<D> {
    override suspend fun invoke(data: D): JsonElement = delegate.invoke(f(data))
}

private class EncodeSdJwtVcSpec(
    private val digestsHashAlgorithm: HashAlgorithm,
    private val option: EncodeAttributesInSdJwtVc.Option,
    private val issuerSigningKey: IssuerSigningKey,
) : EncodeAttributesInSdJwtVc<SdJwtObject> {
    override suspend fun invoke(data: SdJwtObject): JsonElement =
        context(issuerSigningKey, digestsHashAlgorithm, option, NimbusSdJwtOps) {
            val issuer = sdJwtVcIssuer(digestsHashAlgorithm)
            val sdJwt = issuer.issue(data).getOrThrow().also { it.logDebug() }
            when (option) {
                EncodeAttributesInSdJwtVc.Option.Compact -> JsonPrimitive(sdJwt.serialize())
                EncodeAttributesInSdJwtVc.Option.JwsJson -> sdJwt.asJwsJsonObject(JwsSerializationOption.Flattened)
            }
        }
}

context(issuerSigningKey: IssuerSigningKey)
private fun sdJwtVcIssuer(digestsHashAlgorithm: HashAlgorithm): SdJwtIssuer<SignedJWT> {
    val factory = SdJwtFactory(digestsHashAlgorithm)
    val signer = ECDSASigner(issuerSigningKey.key)
    return NimbusSdJwtOps.issuer(factory, signer, issuerSigningKey.signingAlgorithm) {
        type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
        keyID(issuerSigningKey.key.keyID)
        val x5c =
            issuerSigningKey.key.parsedX509CertChain
                .dropRootCA()
                .map { Base64.encode(it.encoded) }
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
