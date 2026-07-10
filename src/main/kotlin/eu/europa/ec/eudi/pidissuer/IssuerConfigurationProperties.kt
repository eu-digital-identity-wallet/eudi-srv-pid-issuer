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
package eu.europa.ec.eudi.pidissuer

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrThrow
import com.eygraber.uri.Url
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.ETSI119472Part3
import eu.europa.ec.eudi.pidissuer.domain.IssuerInfo
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import java.security.interfaces.ECPublicKey
import java.time.Duration as JavaDuration

data class KeycloakConfigurationProperties(
    val serverUrl: Url,
    val authenticationRealm: String,
    val clientId: String,
    val username: String,
    val password: String,
    val userRealm: String,
) {
    init {
        require(authenticationRealm.isNotBlank()) { "'authenticationRealm' cannot be blank" }
        require(clientId.isNotBlank()) { "'clientId' cannot be blank" }
        require(username.isNotBlank()) { "'username' cannot be blank" }
        require(password.isNotBlank()) { "'password' cannot be blank" }
        require(userRealm.isNotBlank()) { "'userRealm' cannot be blank" }
    }
}

@ConfigurationProperties("issuer.metadata")
internal data class IssuerMetadataProperties(
    val preferredClientStatusPeriod: JavaDuration,
    val display: List<DisplayProperties> = emptyList(),
) {
    data class DisplayProperties(
        val name: String? = null,
        val locale: String? = null,
        val logo: LogoProperties? = null,
    )

    data class LogoProperties(
        val uri: String,
        val alternativeText: String? = null,
    )
}

@ConfigurationProperties("issuer.issuerinfo")
internal data class UserInfoProperties(
    val registrationCertificate: List<String>,
) {
    init {
        registrationCertificate
            .forEach { registrationCertificate ->
                val jwt = SignedJWT.parse(registrationCertificate)
                val x5c = jwt.header.x509CertChain
                require(!x5c.isNullOrEmpty()) { "Issuer info must contain a valid certificate chain" }

                val chain = X509CertChainUtils.parse(x5c)
                val leafCert = chain.first()

                val verifier: JWSVerifier =
                    when (val publicKey = leafCert.publicKey) {
                        is ECPublicKey -> {
                            val curve =
                                Curve.forECParameterSpec(publicKey.params)
                                    ?: error("Unsupported EC curve for leaf certificate")
                            ECDSAVerifier(ECKey.Builder(curve, publicKey).build())
                        }

                        else -> {
                            error("Unsupported public key type for leaf certificate")
                        }
                    }

                require(jwt.verify(verifier)) {
                    "JWT signature does not match the public key of the first (leaf) certificate in 'x5c'"
                }
            }
    }

    fun issuerInfo(): NonEmptyList<IssuerInfo> =
        registrationCertificate
            .map { registrationCertificate ->
                IssuerInfo(
                    format = ETSI119472Part3.ISSUER_INFO_FORMAT_REGISTRATION_CERT,
                    data = registrationCertificate,
                )
            }.toNonEmptyListOrThrow()
}

@ConfigurationProperties("issuer.sd-jwt-vc")
internal data class SdJwtVcProperties(
    val typeMetadata: List<TypeMetadataProperties>,
) {
    init {
        val vcts = typeMetadata.map { it.vct }
        require(vcts.size == vcts.distinct().size)
    }

    data class TypeMetadataProperties(
        val vct: String,
        val resource: Resource,
    ) {
        init {
            require(vct.isNotBlank()) { "'vct' cannot be blank" }
            require(resource.exists()) { "'resource' must exist" }
        }
    }
}
