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
package eu.europa.ec.eudi.pidissuer.adapter.out.cfg

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerContext
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.domain.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.pid.PidSdJwtVcV1
import eu.europa.ec.eudi.pidissuer.port.out.cfg.GetCredentialIssuerContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.springframework.core.env.Environment
import java.time.Clock
import java.util.*

class GetCredentialIssuerContextFromEnv(private val env: Environment) : GetCredentialIssuerContext {
    override suspend operator fun invoke(): CredentialIssuerContext = coroutineScope {
        withContext(Dispatchers.IO) {
            val sdJwtVcSigningKey = async { env.sdJwtVcSigningKey() }
            val credentialIssuerMetaData = async { env.credentialIssuerMetaData() }
            CredentialIssuerContext(
                metaData = credentialIssuerMetaData.await(),
                clock = env.clock(),
                sdJwtVcSigningKey = sdJwtVcSigningKey.await(),
            )
        }
    }
}

private fun Environment.clock(): Clock = Clock.systemDefaultZone()
private fun Environment.credentialIssuerMetaData(): CredentialIssuerMetaData {
    val issuerPublicUrl = getRequiredProperty("issuer.publicUrl").run { HttpsUrl.unsafe(this) }
    val authorizationServer = getRequiredProperty("issuer.authorizationServer").run { HttpsUrl.unsafe(this) }
    return CredentialIssuerMetaData(
        id = issuerPublicUrl,
        credentialEndPoint = getRequiredProperty("issuer.publicUrl").run { HttpsUrl.unsafe(this + "/wallet/credentialEndpoint") },
        authorizationServer = authorizationServer,
        credentialsSupported = listOf(PidMsoMdocV1, PidSdJwtVcV1),
    )
}

private fun Environment.sdJwtVcSigningKey(): RSAKey = rsaJwk(clock())
private fun rsaJwk(clock: Clock): RSAKey =
    RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date.from(clock.instant())) // issued-at timestamp (optional)
        .generate()
