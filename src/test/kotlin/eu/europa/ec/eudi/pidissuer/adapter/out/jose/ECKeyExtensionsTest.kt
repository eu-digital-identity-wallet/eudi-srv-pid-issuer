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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlin.test.Test

internal class ECKeyExtensionsTest {

    private val key: ECKey by lazy {
        ECKeyGenerator(Curve.P_256).generate()
    }

    @Test
    internal fun `toPem() must not fail`() {
        key.toPem().also { println(it) }
    }

    @Test
    internal fun `toBase64UrlSafeEncodedPem() must not fail`() {
        key.toBase64UrlSafeEncodedPem().also { println(it) }
    }
}
