# EUDI Android Wallet - OpenID4VCI Issuer Requirements Analysis

This document details what the EUDI Android Wallet reference app expects from an OpenID4VCI credential issuer, based on analysis of the source code of:

- [`eudi-app-android-wallet-ui`](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) (latest release: `2026.02.35`)
- [`eudi-lib-android-wallet-core`](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core) v0.25.0
- [`eudi-lib-jvm-openid4vci-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt) v0.9.1

---

## 1. OpenID4VCI Library

**Library:** `eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt`
**Version used by wallet-core v0.25.0:** `0.9.1`

The app itself does not directly depend on the OpenID4VCI library. Instead it depends on `eudi-lib-android-wallet-core` v0.25.0, which internally uses `eudi-lib-jvm-openid4vci-kt` v0.9.1 as its OpenID4VCI implementation.

The dependency chain is:
```
eudi-app-android-wallet-ui
  └── eudi-lib-android-wallet-core v0.25.0
        └── eudi-lib-jvm-openid4vci-kt v0.9.1
```

---

## 2. Credential Offer Handling

### Supported Offer Methods

The library supports **both** `credential_offer` (pass-by-value) and `credential_offer_uri` (pass-by-reference):

```kotlin
sealed interface CredentialOfferRequest {
    // Pass-by-value: credential_offer query parameter with inline JSON
    value class PassByValue(val value: String) : CredentialOfferRequest

    // Pass-by-reference: credential_offer_uri query parameter with HTTPS URL
    value class PassByReference(val value: HttpsUrl) : CredentialOfferRequest
}
```

The `CredentialOfferRequest.invoke(url)` factory parses the URL and:
- Looks for `credential_offer` query parameter (pass-by-value)
- Looks for `credential_offer_uri` query parameter (pass-by-reference, fetched via HTTP GET)
- Fails if both or neither are present

### Credential Offer JSON Structure

The expected credential offer JSON structure:
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["config_id_1", "config_id_2"],
  "grants": {
    "authorization_code": {
      "issuer_state": "optional_state",
      "authorization_server": "optional_auth_server_url"
    },
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "code_value",
      "tx_code": {
        "input_mode": "numeric",
        "length": 6,
        "description": "Enter the PIN"
      },
      "authorization_server": "optional_auth_server_url"
    }
  }
}
```

### Deep Link Schemes for Credential Offers

The app registers these URI schemes for credential offers:
- `openid-credential-offer://*` (standard OpenID4VCI)
- `haip-vci://*` (HAIP variant)

### Offer Resolution Flow

1. Parse the credential offer URL to extract `credential_offer` or `credential_offer_uri`
2. If `credential_offer_uri`, fetch the offer JSON via HTTP GET
3. Resolve the issuer's metadata from `/.well-known/openid-credential-issuer`
4. Validate that all `credential_configuration_ids` exist in the issuer's metadata
5. Resolve the authorization server metadata from `/.well-known/oauth-authorization-server`

---

## 3. DPoP vs Bearer Token

### Default Configuration: DPoP Enabled

The wallet configures **DPoP by default** using `DPopConfig.Default`:

```kotlin
.withDPopConfig(DPopConfig.Default)
```

### DPoP Behavior

DPoP is **conditional on authorization server support**:

1. During `Issuer.make()`, the library checks `authorizationServerMetadata` for DPoP support
2. `DPopSigner.makeIfSupported()` checks if the AS advertises DPoP signing algorithms
3. If the AS supports DPoP, a `DPoPJwtFactory` is created; otherwise it falls back gracefully to `null` (Bearer)
4. The `IssuerCreator.toOpenId4VCIConfig()` code logs a debug message if DPoP is not supported and sets `dPoPSigner = null`

### Token Types Supported

The library handles both token types:
- `AccessToken.Bearer` - standard Bearer token
- `AccessToken.DPoP` - DPoP-bound token

The credential endpoint client (`CredentialEndpointClient`) uses `bearerOrDPoPAuth()` to set the appropriate authorization header based on the token type.

### DPoP Nonce Handling

The library handles DPoP nonces from both the authorization server and the resource server (credential endpoint). If the resource server responds with `use_dpop_nonce` error and provides a new nonce via `DPoP-Nonce` header, the library retries once with the new nonce.

**Recommendation for your issuer:** Support DPoP if possible. The wallet will use it when available. If your AS doesn't advertise DPoP support, the wallet will fall back to Bearer tokens.

---

## 4. Credential Response Encryption

### Wallet Configuration: `SUPPORTED` (not Required)

The wallet-core hardcodes the encryption policy as **SUPPORTED** (not REQUIRED):

```kotlin
encryptionSupportConfig = EncryptionSupportConfig(
    credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
    ecConfig = EcConfig(ecKeyCurve = Curve.P_256),
    rsaConfig = RsaConfig(rcaKeySize = 2048)
)
```

This means:
- The wallet **supports** encrypted credential responses but does **not require** them
- If the issuer metadata indicates encryption is supported or required, the wallet will use it
- If the issuer doesn't support encryption, the wallet accepts unencrypted responses

### Encryption Parameters

When encryption is used:
- **EC Key Curve:** P-256
- **RSA Key Size:** 2048
- **Supported JWE Algorithms (EC):** All ECDH algorithms supported by Nimbus (ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW)
- **Supported JWE Algorithms (RSA):** All RSA algorithms supported by Nimbus
- **Supported Encryption Methods:** All methods from ContentCryptoProvider (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM, etc.)
- **Compression:** DEF (deflate) supported

### Issuer Metadata for Encryption

The library parses two sections from issuer metadata:

**`credential_response_encryption`** (response encryption):
```json
{
  "alg_values_supported": ["ECDH-ES", "RSA-OAEP"],
  "enc_values_supported": ["A256GCM"],
  "zip_values_supported": ["DEF"],
  "encryption_required": false
}
```

**`credential_request_encryption`** (request encryption, required if response encryption is used):
```json
{
  "jwks": { "keys": [...] },
  "enc_values_supported": ["A256GCM"],
  "zip_values_supported": ["DEF"],
  "encryption_required": false
}
```

**Important:** If the issuer supports/requires credential response encryption, it **must also** advertise `credential_request_encryption` in its metadata. The library validates this constraint.

### Encrypted Response Format

When response encryption is active:
- Response Content-Type: `application/jwt`
- The response body is a JWE-encrypted JWT
- The wallet decrypts it using the key it generated for the session

When no encryption:
- Response Content-Type: `application/json`
- Standard JSON response body

---

## 5. Supported Credential Formats

The OpenID4VCI library v0.9.1 supports these credential format identifiers:

| Format Constant | Value | Description |
|---|---|---|
| `FORMAT_MSO_MDOC` | `mso_mdoc` | ISO mDL / mDoc |
| `FORMAT_SD_JWT_VC` | `dc+sd-jwt` | SD-JWT VC (new "dc+sd-jwt" format) |
| `FORMAT_W3C_JSONLD_DATA_INTEGRITY` | `ldp_vc` | W3C JSON-LD Data Integrity |
| `FORMAT_W3C_JSONLD_SIGNED_JWT` | `jwt_vc_json-ld` | W3C JSON-LD Signed JWT |
| `FORMAT_W3C_SIGNED_JWT` | `jwt_vc_json` | W3C Signed JWT |

### Critical Note on SD-JWT VC Format

**The format identifier for SD-JWT VC is `dc+sd-jwt`** (not the older `vc+sd-jwt`). This is the Digital Credentials format identifier per the latest draft specifications.

In the issuer metadata, the credential configuration should look like:
```json
{
  "format": "dc+sd-jwt",
  "vct": "urn:eu.europa.ec.eudi:pid:1",
  "scope": "eu.europa.ec.eudi.pid.1",
  "cryptographic_binding_methods_supported": ["jwk"],
  "credential_signing_alg_values_supported": ["ES256"],
  "proof_types_supported": {
    "jwt": {
      "proof_signing_alg_values_supported": ["ES256"]
    }
  }
}
```

### Wallet-Core Format Handling

The wallet-core maps formats to its own document types:
- `MsoMdocFormat` - for `mso_mdoc` credentials (identified by `docType`)
- `SdJwtVcFormat` - for `dc+sd-jwt` credentials (identified by `vct`)

The wallet supports issuing and presenting both `MsoMdoc.ES256` and `SdJwtVc.ES256` formats as configured in `WalletCoreConfigImpl`.

### Unknown Format Handling

Any credential configuration with an unrecognized `format` value is silently filtered out during metadata parsing (via `KeepKnownConfigurations` transformer). The wallet will simply not show those credentials.

---

## 6. Nonce Endpoint

### Nonce Endpoint Is Supported (Optional)

The library checks if the issuer metadata contains a `nonce_endpoint` field:

```json
{
  "credential_issuer": "https://issuer.example.com",
  "nonce_endpoint": "https://issuer.example.com/nonce",
  ...
}
```

### Nonce Flow

1. If `nonce_endpoint` is present in issuer metadata, a `NonceEndpointClient` is created
2. Before submitting a credential request, the library may call the nonce endpoint to get a fresh `c_nonce`
3. The nonce endpoint is called via **HTTP POST**
4. Expected response format:
```json
{
  "c_nonce": "some-random-nonce-value"
}
```
5. The library also extracts a DPoP nonce from the response's `DPoP-Nonce` header if present
6. The `c_nonce` is then used in the proof JWT

### If No Nonce Endpoint

If the issuer metadata does not include `nonce_endpoint`, the `NonceEndpointClient` is `null`, and the library relies on other mechanisms for obtaining nonces (e.g., from token endpoint responses or from error responses with `c_nonce`).

---

## 7. Authorization Server Metadata Resolution

### Well-Known URL Used

The library resolves authorization server metadata using:

```
/.well-known/oauth-authorization-server
```

**NOT** `/.well-known/openid-configuration`.

The `DefaultAuthorizationServerMetadataResolver` explicitly constructs the URL as:
```kotlin
private suspend fun fetchOauthServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
    runCatchingCancellable {
        val url = issuer.wellKnownUrl(
            wellKnownPath = "/.well-known/oauth-authorization-server",
        )
        fetchAndParse(url, AuthorizationServerMetadata::parse)
    }
```

### Metadata URL Construction

For an authorization server at `https://auth.example.com`, the resolved URL would be:
```
https://auth.example.com/.well-known/oauth-authorization-server
```

For an authorization server at `https://example.com/auth`, the resolved URL would be:
```
https://example.com/.well-known/oauth-authorization-server/auth
```

### Issuer Metadata Resolution

The credential issuer metadata is resolved from:
```
/.well-known/openid-credential-issuer
```

For issuer `https://issuer.example.com`, the URL would be:
```
https://issuer.example.com/.well-known/openid-credential-issuer
```

### Authorization Server Discovery

The authorization server URL is determined from the issuer metadata:
1. If `authorization_servers` is specified in issuer metadata, uses the first one
2. If `authorization_servers` is not specified, falls back to the credential issuer URL itself

### Required Authorization Server Metadata Fields

For **attestation-based client authentication** (the default in EUDI wallet), the AS metadata must include:
- `token_endpoint` - required for token exchange
- `token_endpoint_auth_methods_supported` - must include `"attest_jwt_client_auth"`
- `client_attestation_signing_alg_values_supported` - JWS algorithms for client attestation JWT
- `client_attestation_pop_signing_alg_values_supported` - JWS algorithms for client attestation PoP JWT
- `challenge_endpoint` - endpoint for attestation challenges
- `authorization_endpoint` - if authorization code grant is used
- `dpop_signing_alg_values_supported` - if DPoP is enabled

---

## 8. Credential Endpoint Request/Response Format

### Credential Request

The credential request is sent as **HTTP POST** to the credential endpoint with:

**Headers:**
- `Content-Type: application/json` (or `application/jwt` if request encryption is enabled)
- `Authorization: Bearer <token>` or `DPoP <token>` (with DPoP proof in `DPoP` header)

**Body (JSON, not encrypted):**
```json
{
  "credential_configuration_id": "eu.europa.ec.eudi.pid_mso_mdoc",
  "proofs": {
    "jwt": ["eyJ..."]
  },
  "credential_response_encryption": {
    "jwk": { ... },
    "alg": "ECDH-ES",
    "enc": "A256GCM"
  }
}
```

Or using `credential_identifier` if available from authorization details:
```json
{
  "credential_identifier": "some_id_from_auth_details",
  "proofs": { ... }
}
```

### Credential Response (Success)

**Without encryption:**
- `Content-Type: application/json`
```json
{
  "credentials": [
    {
      "credential": "eyJ...",
      "c_nonce": "new_nonce",
      "c_nonce_expires_in": 86400
    }
  ]
}
```

**With encryption:**
- `Content-Type: application/jwt`
- Body is a JWE-encrypted JWT containing the same claims

### Proof Types

The library supports these proof types:
1. **JWT proofs** (`jwt`) - Standard JWT proof of possession
2. **Attestation proofs** (`attestation`) - Key attestation-based proofs
3. **JWT proofs with key attestation** - JWT proof + key attestation in header

The proof JWT has type `openid4vci-proof+jwt` and includes the binding key in the header via `jwk`, `kid`, or `x5c`.

### Submission Outcomes

The library handles three outcomes:
- `SubmissionOutcome.Success` - Credential issued, contains `credentials` array
- `SubmissionOutcome.Failed` - Issuance failed with error
- `SubmissionOutcome.Deferred` - Deferred issuance, contains `transaction_id`

---

## 9. Hardcoded Issuer URLs and Configuration

### Demo Flavor (Production-like)

```kotlin
// Primary issuer
"https://issuer.eudiw.dev"
// Secondary issuer
"https://issuer-backend.eudiw.dev"
// Wallet provider
"https://wallet-provider.eudiw.dev"
```

### Dev Flavor (Development)

```kotlin
// Primary issuer
"https://ec.dev.issuer.eudiw.dev"
// Secondary issuer
"https://dev.issuer-backend.eudiw.dev"
// Wallet provider
"https://dev.wallet-provider.eudiw.dev"
```

### Common Configuration for All Issuers

All configured issuers use:
- **Client Authentication:** `AttestationBased` (not `None`)
- **PAR Usage:** `IF_SUPPORTED` (uses PAR if the AS supports it, otherwise falls back to standard auth code flow)
- **DPoP Config:** `Default` (DPoP enabled, uses Android Keystore)
- **Authorization Redirect URI:** Configured via `BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK`

### Deep Link Schemes

```kotlin
val credentialOfferScheme = "openid-credential-offer"
val credentialOfferHaipScheme = "haip-vci"
```

### Scoped Issuance

The credential configuration is derived directly from the issuer's metadata. The wallet auto-discovers available credential types from the issuer's `credential_configurations_supported` in the well-known metadata. No credential types are hardcoded in the wallet app itself - they all come from the issuer metadata.

---

## 10. Summary: What Your Issuer Must Implement

### Required Endpoints

| Endpoint | URL Pattern | Method |
|---|---|---|
| Issuer Metadata | `/.well-known/openid-credential-issuer` | GET |
| Authorization Server Metadata | `/.well-known/oauth-authorization-server` | GET |
| Authorization Endpoint | Configured in AS metadata | GET (browser redirect) |
| Token Endpoint | Configured in AS metadata | POST |
| Credential Endpoint | Configured in issuer metadata | POST |
| Nonce Endpoint (optional) | Configured in issuer metadata | POST |
| Deferred Credential Endpoint (optional) | Configured in issuer metadata | POST |
| Notification Endpoint (optional) | Configured in issuer metadata | POST |

### Issuer Metadata Must Include

```json
{
  "credential_issuer": "https://your-issuer.example.com",
  "authorization_servers": ["https://your-auth-server.example.com"],
  "credential_endpoint": "https://your-issuer.example.com/credential",
  "nonce_endpoint": "https://your-issuer.example.com/nonce",
  "credential_configurations_supported": {
    "your_config_id": {
      "format": "dc+sd-jwt",
      "vct": "your-credential-type",
      "scope": "your-scope",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      }
    }
  }
}
```

### Key Takeaways

1. **Use `dc+sd-jwt` format** (not `vc+sd-jwt`) for SD-JWT VC credentials
2. **Serve AS metadata at `/.well-known/oauth-authorization-server`** (not openid-configuration)
3. **Support DPoP** if possible (wallet uses it by default when available)
4. **Credential response encryption** is supported but not required by the wallet
5. **Nonce endpoint** is optional; if provided, it must respond to POST with `{"c_nonce": "..."}`
6. **Credential offers** support both `credential_offer` (inline) and `credential_offer_uri` (by reference)
7. The wallet uses **attestation-based client authentication** by default, requiring the AS to support `attest_jwt_client_auth`
8. **PAR** is used if the AS advertises support for it
9. For credential offer deep links, use `openid-credential-offer://` scheme
10. The wallet accepts both `application/json` and `application/jwt` (encrypted) responses from the credential endpoint
