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
package eu.europa.ec.eudi.pidissuer.adapter.out.ehic

import arrow.core.Either
import arrow.core.raise.catch
import arrow.core.raise.either
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.IntegrityHashAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.asJwsJsonObject
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObject
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcTypeMetadata
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import kotlin.io.encoding.Base64

sealed interface EncodeEuropeanHealthInsuranceCardInSdJwtVc {
    suspend operator fun invoke(
        ehic: EuropeanHealthInsuranceCard,
        holder: Username,
        holderPublicKey: JWK,
        dateOfIssuance: ZonedDateTime,
        dateOfExpiry: ZonedDateTime,
    ): Either<IssueCredentialError, JsonElement>

    companion object {
        fun jwsJsonFlattened(
            digestsHashAlgorithm: HashAlgorithm,
            issuerSigningKey: IssuerSigningKey,
            integrityHashAlgorithm: IntegrityHashAlgorithm,
            vct: SdJwtVcType,
            credentialIssuerId: CredentialIssuerId,
            typeMetadata: SdJwtVcTypeMetadata,
        ): EncodeEuropeanHealthInsuranceCardInSdJwtVc = JwsJsonFlattenedEncoder(
            digestsHashAlgorithm,
            issuerSigningKey,
            integrityHashAlgorithm,
            vct,
            credentialIssuerId,
            typeMetadata,
        )

        fun compact(
            digestsHashAlgorithm: HashAlgorithm,
            issuerSigningKey: IssuerSigningKey,
            integrityHashAlgorithm: IntegrityHashAlgorithm,
            vct: SdJwtVcType,
            credentialIssuerId: CredentialIssuerId,
            typeMetadata: SdJwtVcTypeMetadata,
        ): EncodeEuropeanHealthInsuranceCardInSdJwtVc = CompactEncoder(
            digestsHashAlgorithm,
            issuerSigningKey,
            integrityHashAlgorithm,
            vct,
            credentialIssuerId,
            typeMetadata,
        )
    }
}

private class JwsJsonFlattenedEncoder(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val integrityHashAlgorithm: IntegrityHashAlgorithm,
    private val vct: SdJwtVcType,
    private val credentialIssuerId: CredentialIssuerId,
    private val typeMetadata: SdJwtVcTypeMetadata,
) : EncodeEuropeanHealthInsuranceCardInSdJwtVc {
    init {
        require(typeMetadata.vct.value == vct.value)
    }

    private val issuer: SdJwtIssuer<SignedJWT> by lazy {
        val factory = SdJwtFactory(digestsHashAlgorithm)
        val signer = ECDSASigner(issuerSigningKey.key)
        NimbusSdJwtOps.issuer(factory, signer, issuerSigningKey.signingAlgorithm) {
            type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
            keyID(issuerSigningKey.key.keyID)
            x509CertChain(issuerSigningKey.key.x509CertChain)
        }
    }

    override suspend operator fun invoke(
        ehic: EuropeanHealthInsuranceCard,
        holder: Username,
        holderPublicKey: JWK,
        dateOfIssuance: ZonedDateTime,
        dateOfExpiry: ZonedDateTime,
    ): Either<IssueCredentialError, JsonElement> = either {
        require(dateOfExpiry >= dateOfIssuance)

        val (vctm, vctmIntegrity) = run {
            val encodedTypeMetadata = Json.encodeToString(typeMetadata)
            val vctm = Base64UrlNoPadding.encode(encodedTypeMetadata.encodeToByteArray())
            val vctmIntegiry = "${integrityHashAlgorithm.id}-${Base64.encode(integrityHashAlgorithm.digest(encodedTypeMetadata))}"
            vctm to vctmIntegiry
        }
        val spec =
            sdJwt(
                vct,
                vctmIntegrity,
                ehic,
                holder,
                holderPublicKey,
                credentialIssuerId,
                dateOfIssuance = dateOfIssuance,
                dateOfExpiry = dateOfExpiry,
            )
        val sdJwt =
            catch({ issuer.issue(spec).getOrThrow() }) {
                raise(IssueCredentialError.Unexpected("Unable to create SD-JWT VC", it))
            }

        val serialized = sdJwt.asJwsJsonObject(JwsSerializationOption.Flattened)
        val existingUnprotectedHeader =
            catch({ serialized[RFC7515.JWS_JSON_HEADER]?.jsonObject }) {
                raise(IssueCredentialError.Unexpected("Unable to get unprotected header of SD-JWT VC", it))
            }
        val updatedUnprotectedHeader = buildJsonObject {
            existingUnprotectedHeader?.forEach { put(it.key, it.value) }
            putJsonArray("vctm") {
                add(vctm)
            }
        }
        val updatedSerialized = buildJsonObject {
            serialized.forEach { put(it.key, it.value) }
            put(RFC7515.JWS_JSON_HEADER, updatedUnprotectedHeader)
        }

        updatedSerialized
    }
}

private fun IntegrityHashAlgorithm.digest(input: String): ByteArray {
    val encodedInput = input.encodeToByteArray()
    return when (this) {
        IntegrityHashAlgorithm.SHA_256 -> MessageDigest.getInstance("SHA-256").digest(encodedInput)
        IntegrityHashAlgorithm.SHA_384 -> MessageDigest.getInstance("SHA-384").digest(encodedInput)
        IntegrityHashAlgorithm.SHA_512 -> MessageDigest.getInstance("SHA-512").digest(encodedInput)
    }
}

private class CompactEncoder(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val integrityHashAlgorithm: IntegrityHashAlgorithm,
    private val vct: SdJwtVcType,
    private val credentialIssuerId: CredentialIssuerId,
    private val typeMetadata: SdJwtVcTypeMetadata,
) : EncodeEuropeanHealthInsuranceCardInSdJwtVc {
    init {
        require(typeMetadata.vct.value == vct.value)
    }

    private val issuer: SdJwtIssuer<SignedJWT> by lazy {
        val factory = SdJwtFactory(digestsHashAlgorithm)
        val signer = ECDSASigner(issuerSigningKey.key)
        val vctm = run {
            val encodedTypeMetadata = Json.encodeToString(typeMetadata)
            Base64UrlNoPadding.encode(encodedTypeMetadata.encodeToByteArray())
        }
        NimbusSdJwtOps.issuer(factory, signer, issuerSigningKey.signingAlgorithm) {
            type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
            keyID(issuerSigningKey.key.keyID)
            x509CertChain(issuerSigningKey.key.x509CertChain)
            customParam("vctm", listOf(vctm))
        }
    }

    override suspend operator fun invoke(
        ehic: EuropeanHealthInsuranceCard,
        holder: Username,
        holderPublicKey: JWK,
        dateOfIssuance: ZonedDateTime,
        dateOfExpiry: ZonedDateTime,
    ): Either<IssueCredentialError, JsonElement> = either {
        require(dateOfExpiry >= dateOfIssuance)

        val vctmIntegrity = run {
            val encodedTypeMetadata = Json.encodeToString(typeMetadata)
            "${integrityHashAlgorithm.id}-${Base64.encode(integrityHashAlgorithm.digest(encodedTypeMetadata))}"
        }
        val spec =
            sdJwt(
                vct,
                vctmIntegrity,
                ehic,
                holder,
                holderPublicKey,
                credentialIssuerId,
                dateOfIssuance = dateOfIssuance,
                dateOfExpiry = dateOfExpiry,
            )
        val sdJwt =
            catch({ issuer.issue(spec).getOrThrow() }) {
                raise(IssueCredentialError.Unexpected("Unable to create SD-JWT VC", it))
            }
        JsonPrimitive(sdJwt.serialize())
    }
}

private fun sdJwt(
    vct: SdJwtVcType,
    vctmIntegrity: String,
    ehic: EuropeanHealthInsuranceCard,
    holder: Username,
    holderPublicKey: JWK,
    credentialIssuerId: CredentialIssuerId,
    dateOfIssuance: ZonedDateTime,
    dateOfExpiry: ZonedDateTime,
): SdJwtObject {
    val formatter: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE

    return sdJwt {
        claim(SdJwtVcSpec.VCT, vct.value)
        claim(SdJwtVcSpec.VCT_INTEGRITY, vctmIntegrity)
        claim(RFC7519.JWT_ID, UUID.randomUUID().toString())
        claim(RFC7519.SUBJECT, holder)
        claim(RFC7519.ISSUER, credentialIssuerId.externalForm)
        claim(RFC7519.ISSUED_AT, dateOfIssuance.toEpochSecond())
        cnf(holderPublicKey)
        claim(RFC7519.EXPIRATION_TIME, dateOfExpiry.toEpochSecond())
        claim(RFC7519.NOT_BEFORE, dateOfIssuance.toEpochSecond())
        sdClaim(EuropeanHealthInsuranceCardClaims.PersonalAdministrativeNumber.name, ehic.personalAdministrativeNumber.value)
        claim(EuropeanHealthInsuranceCardClaims.IssuingCountry.name, ehic.issuingCountry.value)
        objClaim(EuropeanHealthInsuranceCardClaims.IssuingAuthority.attribute.name) {
            claim(EuropeanHealthInsuranceCardClaims.IssuingAuthority.Id.name, ehic.issuingAuthority.id.value)
            claim(EuropeanHealthInsuranceCardClaims.IssuingAuthority.Name.name, ehic.issuingAuthority.name.value)
        }
        claim(EuropeanHealthInsuranceCardClaims.DateOfExpiry.name, formatter.format(dateOfExpiry.withZoneSameInstant(ZoneOffset.UTC)))
        claim(
            EuropeanHealthInsuranceCardClaims.DateOfIssuance.name,
            formatter.format(dateOfIssuance.withZoneSameInstant(ZoneOffset.UTC)),
        )
        objClaim(EuropeanHealthInsuranceCardClaims.AuthenticSource.attribute.name) {
            claim(EuropeanHealthInsuranceCardClaims.AuthenticSource.Id.name, ehic.authenticSource.id.value)
            claim(EuropeanHealthInsuranceCardClaims.AuthenticSource.Name.name, ehic.authenticSource.name.value)
        }
        ehic.endingDate?.let {
            claim(EuropeanHealthInsuranceCardClaims.EndingDate.name, formatter.format(it.withZoneSameInstant(ZoneOffset.UTC)))
        }
        ehic.startingDate?.let {
            claim(EuropeanHealthInsuranceCardClaims.StartingDate.name, formatter.format(it.withZoneSameInstant(ZoneOffset.UTC)))
        }
        sdClaim(EuropeanHealthInsuranceCardClaims.DocumentNumber.name, ehic.documentNumber.value)
    }
}
