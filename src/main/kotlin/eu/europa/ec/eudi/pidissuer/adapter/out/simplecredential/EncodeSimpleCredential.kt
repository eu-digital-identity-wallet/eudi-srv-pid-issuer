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
package eu.europa.ec.eudi.pidissuer.adapter.out.simplecredential

import arrow.core.Either
import arrow.core.raise.catch
import arrow.core.raise.either
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.sdJwtVcIssuer
import eu.europa.ec.eudi.pidissuer.domain.Format
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Instant
import kotlin.uuid.Uuid

interface EncodeSimpleCredential {

    val format: Format
    val type: String

    suspend operator fun invoke(
        simpleCredential: SimpleCredential,
        holderKey: JWK,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError, JsonElement>

    companion object {
        fun sdJwtVcCompact(
            digestsHashAlgorithm: HashAlgorithm,
            issuerSigningKey: IssuerSigningKey,
            vct: SdJwtVcType,
        ): EncodeSimpleCredential = EncodeSimpleCredentialInSdJwtVcCompact(
            digestsHashAlgorithm,
            issuerSigningKey,
            vct,
        )
    }
}

private class EncodeSimpleCredentialInSdJwtVcCompact(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val vct: SdJwtVcType,
) : EncodeSimpleCredential {
    override val format: Format = SD_JWT_VC_FORMAT
    override val type: String = vct.value

    private val issuer: SdJwtIssuer<SignedJWT> by lazy { issuerSigningKey.sdJwtVcIssuer(digestsHashAlgorithm) }

    override suspend fun invoke(
        simpleCredential: SimpleCredential,
        holderKey: JWK,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError, JsonElement> = either {
        val spec = sdJwt {
            claim(RFC7519.JWT_ID, Uuid.random().toHexDashString())
            claim(RFC7519.ISSUED_AT, issuedAt.epochSeconds)
            claim(RFC7519.EXPIRATION_TIME, expiresAt.epochSeconds)
            claim(SdJwtVcSpec.VCT, vct.value)
            cnf(holderKey.toPublicJWK())

            sdClaim(SdJwtVcClaims.FamilyName.name, simpleCredential.familyName.value)
            sdClaim(SdJwtVcClaims.GivenName.name, simpleCredential.givenName.value)
            sdClaim(SdJwtVcClaims.Email.name, simpleCredential.email.value)
            sdClaim(SdJwtVcClaims.DateOfBirth.name, simpleCredential.dateOfBirth.value)
        }

        val sdJwt = catch({
            issuer.issue(spec).getOrThrow()
        }) { raise(IssueCredentialError.Unexpected("Unable to issue SD-JWT VC Simple Credential", it)) }

        with(NimbusSdJwtOps) {
            JsonPrimitive(sdJwt.serialize())
        }
    }
}
