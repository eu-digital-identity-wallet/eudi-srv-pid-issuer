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
package eu.europa.ec.eudi.pidissuer.domain

internal object OpenId4VciSpec {
    const val VERSION = "v1"

    const val SIGNED_METADATA_JWT_TYPE = "openidvci-issuer-metadata+jwt"

    val ZIP_ALGORITHMS = setOf("DEF")

    const val KEY_ATTESTATION_JWT_TYPE = "key-attestation+jwt"

    const val TRANSACTION_ID = "transaction_id"
    const val INTERVAL = "interval"
    const val NOTIFICATION_ID = "notification_id"

    const val CREDENTIAL_RESPONSE_ENCRYPTION = "credential_response_encryption"
}
