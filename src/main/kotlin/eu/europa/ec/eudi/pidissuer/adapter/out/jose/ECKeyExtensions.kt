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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import com.nimbusds.jose.jwk.ECKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.StringWriter
import kotlin.io.encoding.Base64

internal suspend fun ECKey.toPem(): String =
    withContext(Dispatchers.IO) {
        StringWriter().use { stringWriter ->
            PemWriter(stringWriter).use { pemWriter ->
                pemWriter.writeObject(PemObject("PUBLIC KEY", toECPublicKey().encoded))
            }
            stringWriter.toString()
        }
    }

internal suspend fun ECKey.toBase64UrlSafeEncodedPem(): String = Base64.UrlSafe.encode(this.toPem().toByteArray())
