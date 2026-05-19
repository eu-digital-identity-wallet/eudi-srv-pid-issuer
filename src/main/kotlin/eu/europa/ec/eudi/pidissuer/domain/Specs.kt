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
package eu.europa.ec.eudi.pidissuer.domain

import com.nimbusds.jose.JWSAlgorithm

internal object OpenId4VciSpec {
    const val VERSION = "v1"

    const val SIGNED_METADATA_JWT_TYPE = "openidvci-issuer-metadata+jwt"

    val ZIP_ALGORITHMS = setOf("DEF")

    const val KEY_ATTESTATION_JWT_TYPE = "key-attestation+jwt"
    const val KEY_ATTESTATION_ATTESTED_KEYS = "attested_keys"
    const val KEY_ATTESTATION_KEY_STORAGE = "key_storage"
    const val KEY_ATTESTATION_USER_AUTHENTICATION = "user_authentication"
    const val NONCE: String = "nonce"
    const val CERTIFICATION = "certification"

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

/**
 * [Token Status List](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html)
 */
object TokenStatusListSpec {
    const val STATUS: String = "status"
    const val STATUS_LIST: String = "status_list"
    const val IDX: String = "idx"
    const val URI: String = "uri"
}

/**
 * [TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
object TS3 {
    const val KEY_STORAGE_STATUS: String = "key_storage_status"
    const val CLIENT_STATUS: String = "client_status"
    const val PREFERRED_CLIENT_STATUS_PERIOD = "preferred_client_status_period"
    const val PREFERRED_KEY_STORAGE_STATUS_PERIOD = "preferred_key_storage_status_period"

    val SUPPORTED_KEY_ATTESTATION_SIGNING_ALGORITHMS: Set<JWSAlgorithm> =
        setOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
}

object RFC7519 {
    const val ISSUED_AT: String = "iat"
    const val EXPIRES_AT: String = "exp"
}

/**
 * [Electronic Signatures and Trust Infrastructures (ESI); Profiles for Electronic Attestation of Attributes;
 * Part 3: Profiles for issuance of EAA or PID](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf)
 */
object ETSI119472Part3 {
    const val KEY_ATTESTATION_JWT_PROOF_SIGNING_KEY_INDEX: Int = 0
}
