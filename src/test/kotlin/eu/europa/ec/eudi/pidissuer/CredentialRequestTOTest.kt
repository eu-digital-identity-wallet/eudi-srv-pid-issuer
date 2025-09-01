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
package eu.europa.ec.eudi.pidissuer

import eu.europa.ec.eudi.pidissuer.port.input.CredentialRequestTO
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test

class CredentialRequestTOTest {

    @Test
    fun checkMsoMdoc() {
        assert("eu.europa.ec.eudi.pid_mso_mdo" == Json.decodeFromString<CredentialRequestTO>(msoMdoc).credentialConfigurationId)
    }

    @Test
    fun checkSdJwtVc() {
        assert("eu.europa.ec.eudi.pid_vc_sd_jwt" == Json.decodeFromString<CredentialRequestTO>(sdJwtVc).credentialConfigurationId)
    }
}

val msoMdoc = """
    {
       "credential_configuration_id": "eu.europa.ec.eudi.pid_mso_mdo",
       "credential_response_encryption": {
        "jwk": {},
        "enc": "A256CBC-HS512",
        "zip": "DEF"
       },
       "proofs": {
          "jwt": ["eyJraWQiOiJkaWQ6ZXhhbXBsZ"]
       }
    }
""".trimIndent()

val sdJwtVc = """
    {
       "credential_configuration_id": "eu.europa.ec.eudi.pid_vc_sd_jwt",
       "proofs": {
          "jwt":["${
    """
                eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
                xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
                0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbm
                NlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM        
    """.trimIndent().replace("\n","")
}"]
       }
    }
""".trimIndent()
