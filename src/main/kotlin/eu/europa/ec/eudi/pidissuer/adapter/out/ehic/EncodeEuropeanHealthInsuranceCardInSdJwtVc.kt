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
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.asJwsJsonObject
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObject
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import kotlin.time.Instant
import kotlin.time.toJavaInstant

sealed interface EncodeEuropeanHealthInsuranceCardInSdJwtVc {
    suspend operator fun invoke(
        ehic: EuropeanHealthInsuranceCard,
        holder: Username,
        holderPublicKey: JWK,
        dateOfIssuance: Instant,
        dateOfExpiry: Instant,
    ): Either<IssueCredentialError, JsonElement>

    companion object {
        fun jwsJsonFlattened(
            digestsHashAlgorithm: HashAlgorithm,
            issuerSigningKey: IssuerSigningKey,
            vct: SdJwtVcType,
            credentialIssuerId: CredentialIssuerId,
        ): EncodeEuropeanHealthInsuranceCardInSdJwtVc = JwsJsonFlattenedEncoder(
            digestsHashAlgorithm,
            issuerSigningKey,
            vct,
            credentialIssuerId,
        )

        fun compact(
            digestsHashAlgorithm: HashAlgorithm,
            issuerSigningKey: IssuerSigningKey,
            vct: SdJwtVcType,
            credentialIssuerId: CredentialIssuerId,
        ): EncodeEuropeanHealthInsuranceCardInSdJwtVc = CompactEncoder(
            digestsHashAlgorithm,
            issuerSigningKey,
            vct,
            credentialIssuerId,
        )
    }
}

private class JwsJsonFlattenedEncoder(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val vct: SdJwtVcType,
    private val credentialIssuerId: CredentialIssuerId,
) : EncodeEuropeanHealthInsuranceCardInSdJwtVc {
    private val issuer: SdJwtIssuer<SignedJWT> by lazy { issuerSigningKey.issuer(digestsHashAlgorithm) }

    override suspend operator fun invoke(
        ehic: EuropeanHealthInsuranceCard,
        holder: Username,
        holderPublicKey: JWK,
        dateOfIssuance: Instant,
        dateOfExpiry: Instant,
    ): Either<IssueCredentialError, JsonElement> = either {
        val sdJwt = catch({
            issuer.createSdJwt(vct, ehic, holder, holderPublicKey, credentialIssuerId, dateOfIssuance, dateOfExpiry)
        }) { raise(IssueCredentialError.Unexpected("Unable to create SD-JWT VC", it)) }

        sdJwt.asJwsJsonObject(JwsSerializationOption.Flattened)
    }
}

private class CompactEncoder(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val vct: SdJwtVcType,
    private val credentialIssuerId: CredentialIssuerId,
) : EncodeEuropeanHealthInsuranceCardInSdJwtVc {
    private val issuer: SdJwtIssuer<SignedJWT> by lazy { issuerSigningKey.issuer(digestsHashAlgorithm) }

    override suspend operator fun invoke(
        ehic: EuropeanHealthInsuranceCard,
        holder: Username,
        holderPublicKey: JWK,
        dateOfIssuance: Instant,
        dateOfExpiry: Instant,
    ): Either<IssueCredentialError, JsonElement> = either {
        val sdJwt = catch({
            issuer.createSdJwt(vct, ehic, holder, holderPublicKey, credentialIssuerId, dateOfIssuance, dateOfExpiry)
        }) { raise(IssueCredentialError.Unexpected("Unable to create SD-JWT VC", it)) }

        JsonPrimitive(sdJwt.serialize())
    }
}

private fun sdJwt(
    vct: SdJwtVcType,
    ehic: EuropeanHealthInsuranceCard,
    holder: Username,
    holderPublicKey: JWK,
    credentialIssuerId: CredentialIssuerId,
    dateOfIssuance: Instant,
    dateOfExpiry: Instant,
): SdJwtObject {
    val formatter: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE

    return sdJwt {
        claim(SdJwtVcSpec.VCT, vct.value)
        claim(RFC7519.JWT_ID, UUID.randomUUID().toString())
        claim(RFC7519.SUBJECT, holder)
        claim(RFC7519.ISSUER, credentialIssuerId.externalForm)
        claim(RFC7519.ISSUED_AT, dateOfIssuance.epochSeconds)
        cnf(holderPublicKey)
        claim(RFC7519.EXPIRATION_TIME, dateOfExpiry.epochSeconds)
        claim(RFC7519.NOT_BEFORE, dateOfIssuance.epochSeconds)
        sdClaim(EuropeanHealthInsuranceCardClaims.PersonalAdministrativeNumber.name, ehic.personalAdministrativeNumber.value)
        claim(EuropeanHealthInsuranceCardClaims.IssuingCountry.name, ehic.issuingCountry.value)
        objClaim(EuropeanHealthInsuranceCardClaims.IssuingAuthority.attribute.name) {
            claim(EuropeanHealthInsuranceCardClaims.IssuingAuthority.Id.name, ehic.issuingAuthority.id.value)
            claim(EuropeanHealthInsuranceCardClaims.IssuingAuthority.Name.name, ehic.issuingAuthority.name.value)
        }
        claim(
            EuropeanHealthInsuranceCardClaims.DateOfExpiry.name,
            formatter.format(ZonedDateTime.ofInstant(dateOfExpiry.toJavaInstant(), ZoneOffset.UTC)),
        )
        claim(
            EuropeanHealthInsuranceCardClaims.DateOfIssuance.name,
            formatter.format(ZonedDateTime.ofInstant(dateOfIssuance.toJavaInstant(), ZoneOffset.UTC)),
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

private fun IssuerSigningKey.issuer(digestsHashAlgorithm: HashAlgorithm): SdJwtIssuer<SignedJWT> {
    val factory = SdJwtFactory(digestsHashAlgorithm)
    val signer = ECDSASigner(key)
    return NimbusSdJwtOps.issuer(factory, signer, signingAlgorithm) {
        type(JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT))
        keyID(key.keyID)
        x509CertChain(key.x509CertChain)
    }
}

private suspend fun SdJwtIssuer<SignedJWT>.createSdJwt(
    vct: SdJwtVcType,
    ehic: EuropeanHealthInsuranceCard,
    holder: Username,
    holderPublicKey: JWK,
    credentialIssuerId: CredentialIssuerId,
    dateOfIssuance: Instant,
    dateOfExpiry: Instant,
): SdJwt<SignedJWT> {
    require(dateOfExpiry >= dateOfIssuance)

    val spec = sdJwt(
        vct = vct,
        ehic = ehic,
        holder = holder,
        holderPublicKey = holderPublicKey,
        credentialIssuerId = credentialIssuerId,
        dateOfIssuance = dateOfIssuance,
        dateOfExpiry = dateOfExpiry,
    )

    return issue(spec).getOrThrow()
}
