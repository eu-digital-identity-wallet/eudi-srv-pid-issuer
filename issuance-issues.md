# Issuance improvement issues

## P0 — Clarity & hygiene

1. ~~**Rename terse type aliases** — `IssRequest` / `IssError` → `PlainOrEncrypted<T>` / `CredentialOrEncryptedError<E>`.~~ ✅ DONE

2. ~~**String interpolation in logging** — `log.warn("Failed to issue credential $error")` uses Kotlin interpolation (always evaluated) instead of SLF4J `{}` parameterized form.~~ ✅ DONE

## P1 — Code quality & maintainability

3. ~~**Move client status check before request parsing** — The `ensure` against `preferredClientStatusPeriod` runs after `credentialRequestTO.toDomain()`. Moving it earlier rejects expired requests without parsing the body.~~ ✅ DONE

4. ~~**`toDomain()` is 85 lines** — Split into `checkBatchIssuance()`, `extractProof()`, `buildCredentialRequest()`, `resolveRequest()`.~~ ✅ DONE

5. ~~**`Services` inner class indirection** — All business logic lives in a `private class Services` inside `IssueCredential`. Inlined into the outer class, renamed inner method to `doIssueCredential`.~~ ✅ DONE

6. ~~**`JWT_VS_JSON_FORMAT` explicit rejection** — Added comment explaining why JwtVcJson is rejected at issuance (advertised in metadata but not implemented for issuance).~~ ✅ DONE

## P2 — Test coverage

7. **No direct unit tests for `IssueCredential`** — Only tested indirectly via `WalletApiTest` (integration). No isolated `IssueCredentialTest.kt` exists.

## Non-issues (investigated and closed)

- **`assertIsSupported` visibility** — Top-level function in `domain/CredentialRequest.kt`, imported via wildcard `domain.*`. Fully visible.
- **N+1 `assertIsSupported` calls** — The `filter`-then-`find` pattern is deliberate: it provides distinct `UnsupportedCredentialType` vs `UnsupportedCredentialConfigurationId` errors.
