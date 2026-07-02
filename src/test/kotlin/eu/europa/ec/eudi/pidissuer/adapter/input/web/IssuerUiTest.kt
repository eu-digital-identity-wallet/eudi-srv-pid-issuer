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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.expectContentSecurityPolicy
import kotlinx.coroutines.test.runTest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.test.web.reactive.server.WebTestClient
import kotlin.test.Test

@PidIssuerApplicationTest
class IssuerUiTest {
    @Autowired
    private lateinit var applicationContext: ApplicationContext

    private fun client(): WebTestClient =
        WebTestClient
            .bindToApplicationContext(applicationContext)
            .configureClient()
            .build()

    @Test
    fun `verify ui path contains enforcing csp header`() =
        runTest {
            client()
                .get()
                .uri(IssuerUi.GENERATE_CREDENTIALS_OFFER)
                .exchange()
                .expectStatus()
                .isOk
                .expectContentSecurityPolicy(enforcing = true)
        }
}
