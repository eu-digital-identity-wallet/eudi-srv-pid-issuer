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
package eu.europa.ec.eudi.pidissuer.adapter.out.webclient

import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import org.slf4j.LoggerFactory
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient

private val log = LoggerFactory.getLogger(WebClients::class.java)

/**
 * Factories for [WebClient].
 */
internal object WebClients {

    /**
     * Creates a new [WebClient].
     */
    fun default(customizer: WebClient.Builder.() -> Unit = {}): WebClient =
        WebClient.builder()
            .apply(customizer)
            .build()

    /**
     * Creates an *insecure* [WebClient] that trusts all certificates.
     */
    fun insecure(customizer: WebClient.Builder.() -> Unit = {}): WebClient {
        log.warn("Using insecure WebClient trusting all certificates")
        val sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        val httpClient = HttpClient.create().secure { it.sslContext(sslContext) }
        return WebClient.builder()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .apply(customizer)
            .build()
    }
}
