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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import kotlinx.coroutines.test.runTest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import kotlin.test.Test

@PidIssuerApplicationTest
internal class MetaDataApiTest {

    @Autowired
    private lateinit var applicationContext: ApplicationContext

    private fun client(): WebTestClient =
        WebTestClient.bindToApplicationContext(applicationContext)
            .configureClient()
            .build()

    private val MEDIA_TYPE_APPLICATION_JWT = MediaType("application", "jwt")

    @Test
    fun `returns signed credential issuer metadata when accept header is ANY`() = runTest {
        client()
            .get()
            .uri(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER)
            .accept(MediaType.ALL)
            .exchange()
            .expectStatus().isOk()
            .expectHeader().contentType(MEDIA_TYPE_APPLICATION_JWT)
            .expectBody<String>()
    }

    @Test
    fun `returns signed credential issuer metadata when accept header is empty`() = runTest {
        client()
            .get()
            .uri(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER)
            .exchange()
            .expectStatus().isOk()
            .expectHeader().contentType(MEDIA_TYPE_APPLICATION_JWT)
            .expectBody<String>()
    }

    @Test
    fun `returns signed credential issuer metadata when accept header is JWT`() = runTest {
        client()
            .get()
            .uri(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER)
            .accept(MEDIA_TYPE_APPLICATION_JWT)
            .exchange()
            .expectStatus().isOk()
            .expectHeader().contentType(MEDIA_TYPE_APPLICATION_JWT)
            .expectBody<String>()
    }

    @Test
    fun `returns unsigned credential issuer metadata when accept header is Json`() = runTest {
        client()
            .get()
            .uri(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody<String>()
    }
}
