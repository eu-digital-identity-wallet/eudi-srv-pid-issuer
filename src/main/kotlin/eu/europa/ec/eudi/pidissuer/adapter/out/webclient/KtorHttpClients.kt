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
import io.ktor.client.engine.java.*
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.net.http.HttpClient
import io.ktor.client.HttpClient as KtorHttpClient
import io.ktor.client.engine.java.Java as JavaEngine

/**
 * [KtorHttpClient] instances for usage within the application.
 */
internal object KtorHttpClients {
    operator fun invoke(
        proxy: HttpProxy? = null,
        secure: Boolean = true,
    ) = KtorHttpClient(JavaEngine) {
        engine {
            configureProxy(proxy)
            config { sslCtx(secure) }
        }
    }

    /**
     * A [KtorHttpClient] with default settings.
     */
    fun default(proxy: HttpProxy?): KtorHttpClient = invoke(proxy, true)

    /**
     * A [KtorHttpClient] that trusts *all* certificates.
     */
    fun insecure(proxy: HttpProxy?): KtorHttpClient = invoke(proxy, false)
}

private fun HttpClient.Builder.sslCtx(secure: Boolean = true) {
    if (secure) return
    val sslContext =
        javax.net.ssl.SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf(InsecureTrustManagerFactory.INSTANCE.trustManagers[0]), null)
        }
    sslContext(sslContext)
    log.warn("Using insecure KtorHttpClient trusting all certificates")
}

private fun JavaHttpConfig.configureProxy(proxy: HttpProxy?) {
    proxy?.let { httpProxy ->
        log.info("Using KtorHttpClient with proxy settings")
        this.proxy = httpProxy.toJavaProxy()
    }
}

private fun HttpProxy.toJavaProxy(): java.net.Proxy =
    java.net.Proxy(
        java.net.Proxy.Type.HTTP,
        java.net.InetSocketAddress(url.host, url.port),
    )
