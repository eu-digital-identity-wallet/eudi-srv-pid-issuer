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
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient

/**
 * [WebClient] instances for usage in the application.
 */
internal object WebClients {

    private val log = LoggerFactory.getLogger(WebClients::class.java)

    /**
     * A [WebClient] with JSON serialization/deserialization enabled using Kotlin-X Serialization.
     */
    val Default: WebClient by lazy {
        val json = Json { ignoreUnknownKeys = true }
        WebClient.builder()
            .codecs {
                it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
                it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
                it.defaultCodecs().enableLoggingRequestDetails(true)
            }
            .build()
    }

    /**
     * A [WebClient] with JSON serialization/deserialization enabled using Kotlin-X Serialization
     * that trusts all SSL certificates.
     */
    val Insecure: WebClient by lazy {
        log.warn("Using insecure WebClient trusting all certificates")
        val sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        val httpClient = HttpClient.create().secure { it.sslContext(sslContext) }
        Default.mutate()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .build()
    }
}
