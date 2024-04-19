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
package eu.europa.ec.eudi.pidissuer.adapter.out.w3c

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.*

interface Realizer<in PM : ProofMechanism, out VC : W3CVerifiableCredential> {

    fun realize(credential: W3CCredential, proofMechanism: PM): VC
}

class JwtVcJsonRealizer : Realizer<ProofMechanism.JWT, W3CVerifiableCredential.JwtVcJson> {

    override fun realize(
        credential: W3CCredential,
        proofMechanism: ProofMechanism.JWT,
    ): W3CVerifiableCredential.JwtVcJson {
        require(credential.credentialSubject.size == 1) { "Only one credential subject is supported for jwt_vc_json format realization" }

        val (signingKey, signingAlgorithm) = proofMechanism

        val header = JWSHeader.Builder(signingAlgorithm)
        header.type(JOSEObjectType.JWT)
        header.jwk(signingKey.toPublicJWK())

        val claimsSet = JWTClaimsSet.Builder()

        with(credential.metadata) {
            // iss MUST represent the issuer property of a verifiable credential.
            claimsSet.issuer(issuer.toString())
            // nbf MUST represent issuanceDate, encoded as a UNIX timestamp (NumericDate).
            claimsSet.notBeforeTime(Date.from(issuanceDate))
            // exp MUST represent the expirationDate property, encoded as a UNIX timestamp (NumericDate).
            claimsSet.expirationTime(Date.from(expirationDate))
            // jti MUST represent the id property of the verifiable credential.
            id?.let { claimsSet.jwtID(id.toString()) }
        }
        // sub MUST represent the id property contained in the credentialSubject
        credential.credentialSubject[0].id?.let {
            claimsSet.subject(credential.credentialSubject[0].id.toString())
        }
        claimsSet.claim("vc", JSONObjectUtils.parse(Json.encodeToString(credential.toJsonObject())))

        val signer = DefaultJWSSignerFactory().createJWSSigner(signingKey, signingAlgorithm)
        val signedJWT = SignedJWT(header.build(), claimsSet.build()).apply { sign(signer) }

        return W3CVerifiableCredential.JwtVcJson(signedJWT)
    }
}
