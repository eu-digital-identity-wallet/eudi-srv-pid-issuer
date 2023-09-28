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
package eu.europa.ec.eudi.pidissuer.port.out.cfg

import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerContext
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import org.springframework.core.env.Environment
import java.time.Clock

class GetCredentialIssuerContextFromEnv(private val env: Environment) : GetCredentialIssuerContext {
    override fun invoke(): CredentialIssuerContext =
        CredentialIssuerContext(
            metaData = env.credentialIssuerMetaData(),
            clock = env.clock(),
        )
}

private fun Environment.clock(): Clock = Clock.systemDefaultZone()
private fun Environment.credentialIssuerMetaData(): CredentialIssuerMetaData {
    val issuerPublicUrl = getRequiredProperty("issuer.publicUrl").run { HttpsUrl.unsafe(this) }
    val authorizationServer = getRequiredProperty("issuer.authorizationServer").run { HttpsUrl.unsafe(this) }
    return CredentialIssuerMetaData(
        id = issuerPublicUrl,
        credentialEndPoint = getRequiredProperty("issuer.publicUrl").run { HttpsUrl.unsafe(this + "/wallet/credentialEndpoint") },
        authorizationServer = authorizationServer,
        credentialsSupported = listOf(PidMsoMdocV1),
    )
}
