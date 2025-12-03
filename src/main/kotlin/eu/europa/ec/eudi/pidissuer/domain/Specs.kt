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

/**
 * [Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
 */
object RFC9728 {
    const val RESOURCE: String = "resource"
    const val AUTHORIZATION_SERVERS: String = "authorization_servers"
    const val SCOPES_SUPPORTED: String = "scopes_supported"
    const val BEARER_METHODS_SUPPORTED: String = "bearer_methods_supported"
    const val DPOP_SIGNING_ALGORITHMS_SUPPORTED: String = "dpop_signing_alg_values_supported"
    const val DPOP_BOUND_ACCESS_TOKEN_REQUIRED: String = "dpop_bound_access_tokens_required"

    const val BEARER_METHOD_HEADER: String = "header"
    const val BEARER_METHOD_BODY: String = "body"
    const val BEARER_METHOD_QUERY: String = "query"
}
