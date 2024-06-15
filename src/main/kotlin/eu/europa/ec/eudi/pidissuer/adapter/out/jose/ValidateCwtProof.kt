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

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import com.authlete.cbor.*
import com.authlete.cose.COSEEC2Key
import com.authlete.cose.COSEProtectedHeader
import com.authlete.cose.COSESign1
import com.authlete.cose.COSEVerifier
import com.authlete.cwt.CWT
import com.authlete.cwt.CWTClaimsSet
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import java.time.Clock
import java.time.Instant
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration.Companion.minutes

context (Raise<IssueCredentialError.InvalidProof>)
fun validateCwtProof(
    credentialIssuerId: CredentialIssuerId,
    unvalidatedProof: UnvalidatedProof.Cwt,
    expectedCNonce: CNonce,
    credentialConfiguration: CredentialConfiguration,
): CredentialKey {
    val proofType = credentialConfiguration.proofTypesSupported[ProofTypeEnum.CWT]
    ensureNotNull(proofType) {
        IssueCredentialError.InvalidProof("credential configuration '${credentialConfiguration.id.value}' doesn't support 'jwt' proofs")
    }
    check(proofType is ProofType.Cwt)

    return validateCwtProof(credentialIssuerId, unvalidatedProof, expectedCNonce, proofType)
}

context (Raise<IssueCredentialError.InvalidProof>)
fun validateCwtProof(
    credentialIssuerId: CredentialIssuerId,
    unvalidatedProof: UnvalidatedProof.Cwt,
    expectedCNonce: CNonce,
    proofType: ProofType.Cwt,
): CredentialKey {
    return CwtProofValidator.isValid(
        Clock.systemDefaultZone(),
        iss = null,
        aud = credentialIssuerId,
        nonce = expectedCNonce,
        p = unvalidatedProof,
    ).getOrElse {
        raise(IssueCredentialError.InvalidProof("Reason: " + it.message))
    }
}

internal object CwtProofValidator {

    fun isValid(
        clock: Clock,
        iss: String?,
        aud: CredentialIssuerId,
        nonce: CNonce,
        p: UnvalidatedProof.Cwt,
    ): Result<CredentialKey> = runCatching {
        val (credentialKey, claimSet) = claimSet(p)
        if (iss != null) {
            require(iss == claimSet.iss) {
                "Invalid CWT proof. Expecting iss=$iss found ${claimSet.iss}"
            }
        }
        require(aud.toString() == claimSet.aud) {
            "Invalid CWT proof. Expecting aud=$aud found ${claimSet.aud}"
        }
        require(nonce.nonce == claimSet.nonce.toString(Charsets.UTF_8)) {
            "Invalid CWT proof. Expecting nonce=${nonce.nonce}"
        }
        val claimSetIat = requireNotNull(claimSet.iat) {
            "Invalid CWT proof. Missing iat"
        }
        val now = Instant.now()
        val skew = 3.minutes.inWholeSeconds // seconds
        val range = now.minusSeconds(skew).epochSecond..now.plusSeconds(skew).epochSecond
        require(claimSetIat.toInstant().epochSecond in range) {
            "Invalid CWT proof. Invalid iat"
        }
        credentialKey
    }

    private fun claimSet(p: UnvalidatedProof.Cwt): Pair<CredentialKey, CWTClaimsSet> {
        val cwt = ensureIsCWT(p)
        val sign1 = ensureContainsSignOneMessage(cwt)
        val credentialKey = verifySignature(sign1)
        return credentialKey to claimSet(sign1)
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun ensureIsCWT(p: UnvalidatedProof.Cwt): CWT {
        val cwtInBytes = Base64.UrlSafe.decode(p.cwt)
        val cborItem = CBORDecoder(cwtInBytes).next()
        require(cborItem is CWT) { "Not CBOR CWT" }
        return cborItem
    }

    private fun ensureContainsSignOneMessage(cwt: CWT): COSESign1 {
        val message = cwt.message
        require(message is COSESign1) { "CWT does not contain a COSE Sign one message" }
        return message
    }

    private fun verifySignature(sign1: COSESign1): CredentialKey {
        val credentialKey = ensureValidProtectedHeader(sign1)
        val coseKey = when (credentialKey) {
            is CredentialKey.DIDUrl -> error("Unsupported")
            is CredentialKey.Jwk -> {
                require(credentialKey.value is ECKey)
                credentialKey.value.toPublicKey()
            }

            is CredentialKey.X5c -> {
                credentialKey.certificate.publicKey
            }
        }
        require(COSEVerifier(coseKey).verify(sign1)) { "Invalid signature" }
        return credentialKey
    }

    private fun ensureValidProtectedHeader(sign1: COSESign1): CredentialKey {
        val pHeader: COSEProtectedHeader = sign1.protectedHeader
        require("openid4vci-proof+cwt" == pHeader.contentType) { "Invalid content type ${pHeader.contentType}" }

        val coseKey = run {
            val coseKeyAsByteString = pHeader.pairs.firstOrNull { (key, value) ->
                key is CBORString && key.value == "COSE_Key" &&
                    value is CBORByteArray
            }?.value as CBORByteArray?
            val cborItem = coseKeyAsByteString?.let { CBORDecoder(it.value).next() }

            cborItem?.takeIf { it is CBORPairList }?.let { item ->
                check(item is CBORPairList)
                COSEEC2Key(item.pairs)
            }
        }

        val x5cChain = pHeader.x5Chain.orEmpty()
        require(!(null != coseKey && x5cChain.isNotEmpty())) {
            "Cannot have both a COSE_Key and x5c chain"
        }
        return if (coseKey != null) {
            val authJwk = coseKey.toJwk()
            val jwk: JWK = JWK.parse(authJwk)
            require(jwk is ECKey)
            CredentialKey.Jwk(jwk)
        } else {
            CredentialKey.X5c(checkNotNull(x5cChain.toNonEmptyListOrNull()))
        }
    }

    private fun claimSet(sign1: COSESign1): CWTClaimsSet {
        val payload = sign1.payload
        val parsed = payload.parse()
        val listOfPairs = CBORDecoder(parsed as ByteArray).next() as CBORPairList
        return CWTClaimsSet(listOfPairs.pairs)
    }
}

private operator fun CBORPair.component1(): CBORItem = key
private operator fun CBORPair.component2(): CBORItem = value
