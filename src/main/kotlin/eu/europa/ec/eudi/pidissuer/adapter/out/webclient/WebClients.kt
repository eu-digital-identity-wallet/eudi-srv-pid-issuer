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
package eu.europa.ec.eudi.pidissuer.adapter.out.webclient

import eu.europa.ec.eudi.pidissuer.log
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import kotlinx.serialization.json.Json
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import reactor.netty.transport.ProxyProvider

/**
 * [WebClient] instances for usage within the application.
 */
internal object WebClients {
    operator fun invoke(
        proxy: HttpProxy?,
        secure: Boolean = true,
    ): WebClient {
        val httpClient =
            when (secure) {
                true -> {
                    httpClient(proxy)
                }

                false -> {
                    log.warn("Using insecure WebClient trusting all certificates")
                    val sslContext =
                        SslContextBuilder
                            .forClient()
                            .trustManager(InsecureTrustManagerFactory.INSTANCE)
                            .build()
                    httpClient(proxy).secure { it.sslContext(sslContext) }
                }
            }
        return WebClient
            .builder()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .configureCodecs()
            .build()
    }

    fun default(proxy: HttpProxy?): WebClient = invoke(proxy, true)

    fun insecure(proxy: HttpProxy?): WebClient = invoke(proxy, false)
}

private fun httpClient(proxy: HttpProxy? = null): HttpClient {
    if (proxy == null) {
        return HttpClient.create()
    }
    return HttpClient.create().proxy { proxyProvider ->
        log.info("Using WebClient with proxy settings")
        proxyProvider
            .type(ProxyProvider.Proxy.HTTP)
            .host(proxy.url.host)
            .port(proxy.url.port)
            .apply {
                proxy.username?.let {
                    username(it)
                    password { proxy.password ?: "" }
                }
            }
    }
}

private fun WebClient.Builder.configureCodecs(): WebClient.Builder {
    val json = Json { ignoreUnknownKeys = true }

    return codecs {
        it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
        it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
        it.defaultCodecs().enableLoggingRequestDetails(true)
    }
}
