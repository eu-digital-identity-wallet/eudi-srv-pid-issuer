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
package eu.europa.ec.eudi.pidissuer.adapter.out.credential

import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.port.out.credential.GenerateCNonce
import java.time.Clock
import java.time.Duration

/**
 * Default implementation for [GenerateCNonce].
 */
internal class DefaultGenerateCNonce(
    private val clock: Clock,
    private val expiresIn: Duration,
    private val generator: suspend () -> String = { Nonce(128).value },
) : GenerateCNonce {
    override suspend fun invoke(): CNonce = CNonce(generator(), clock.instant(), expiresIn)
}
