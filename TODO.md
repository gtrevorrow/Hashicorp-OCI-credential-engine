# Project TODO

This file is the working backlog for the OCI credential engine plugin. It tracks implementation gaps, follow-up work, and deferred ideas so they do not get lost in the README.

## Active Backlog

### Current Implemented State

- [x] Direct caller-supplied subject-token exchange remains the primary integration path.
- [x] Plugin-issued subject-token mode is implemented: when `subject_token` is omitted and `enable_plugin_issued_subject_token=true`, the plugin tries Vault `GenerateIdentityToken` first and falls back to self-mint only when self-mint is explicitly enabled and configured.
- [x] Explicit brokered subject-token mode is implemented: the plugin can validate a caller-supplied JWT locally, map validated claims with templates, self-mint a plugin-issued brokered JWT, and exchange that re-issued JWT with OCI.
- [x] Brokered trust sources support OIDC discovery, JWKS URL, inline JWKS JSON, and inline public keys, with issuer, audience, algorithm, and time-claim validation.
- [x] Role-scoped `self_mint_custom_claims` are implemented for plugin-issued self-mint and brokered re-issue flows when an explicit `/exchange/:role` path is selected.
- [x] RPST exchange requests send `rpst_exp` based on the effective TTL after request, role, and backend TTL policy are applied. UPST lifetime remains OCI-controlled; plugin TTLs primarily affect Vault lease metadata for UPST responses.
- [x] Single-key JWKS export is implemented at `oci/jwks` for the configured self-mint signing key, including stable `kid` and compatibility `x5c` output.
- [x] Unit and handler-level tests cover config, roles, direct exchange validation, plugin-issued subject-token flow, self-mint claims, brokered re-issue, JWKS export, and mock OCI client integration behavior.

### Operational Hardening

- [ ] Add metrics and telemetry for token exchange rate, error rate, and latency
- [ ] Build full end-to-end tests against an OCI sandbox, disposable test domain, or test tenancy
- [ ] Add a documented operational runbook for self-mint key rollover and JWKS republishing
- [ ] Harden `subject_token_allowed_audiences` handling beyond current trim/dedupe behavior:
  - reject empty entries instead of silently dropping them
  - reject control characters
  - enforce a reasonable per-audience length limit
  - normalize `subject_token_audience` request values before comparison

### FIPS Readiness

- [ ] Document what "usable in Vault Enterprise FIPS deployments" means for this external plugin versus claiming the plugin itself is inside a FIPS-validated crypto boundary
- [ ] Review the plugin's direct crypto usage (RSA key generation, JWT signing, TLS client behavior, X.509 handling) for FIPS-oriented deployment expectations
- [ ] Confirm whether additional hardening or build constraints are needed for external plugin binaries in Vault Enterprise FIPS deployments

### Self-Mint and JWKS

- [ ] Add self-mint key rotation with overlapping verification keys
- [ ] Publish multi-key JWKS during rotation; current JWKS export publishes only the active configured signing key
- [ ] Add an explicit rotate/promote/retire workflow for self-mint signing keys

## Deferred / Optional Work

These items are intentionally deferred. They are not part of the current preferred design, but they may become relevant later.

### Optional Future Mode: Plugin-Issued Subject Tokens

- [ ] Add support for multiple issuers or IdPs per backend in plugin-issued token mode
- [ ] Add broader claims mapping or policy translation for plugin-issued token mode beyond the existing role-scoped `self_mint_custom_claims`

### Brokered Mode Follow-Up

- [ ] Decide whether brokered-only deployments should be able to read `oci/jwks` without setting `subject_token_self_mint_enabled=true`
- [ ] Consider enforcing HTTPS-only brokered remote trust sources (`oidc_discovery` and `jwks_url`) or documenting the non-HTTPS risk more prominently
- [ ] Evaluate replay-hardening options for brokered JWTs, such as optional `jti` or nonce tracking, if operational requirements justify stateful validation
- [ ] Keep `DESIGN_BROKERED_SUBJECT_TOKEN_MODE.md` as the design record, but treat the implemented behavior in `README.md`, `THREAT_MODEL.md`, `TEST_PLAN.md`, and `oci-backend/` as the current source of truth

## Explicit Non-Goals For Now

- General external REST callback pluggability for subject-token resolution
- Caller-controlled identity-selection claims in self-minted tokens
- Making Vault-authenticated `oci/jwks` the direct OCI discovery endpoint

## Current Design Notes

- Primary integration path: caller supplies `subject_token`
- Optional plugin-issued subject-token mode: `GenerateIdentityToken` first, then self-mint only if needed and configured
- Brokered subject-token mode is now implemented as an explicit opt-in mode, not only a future design
- OCI remains the authority for token validation, token exchange trust, and final authorization mapping
- In direct pass-through mode, OCI validates the caller-supplied subject token; in brokered mode, the plugin validates the external token and OCI validates the plugin-issued brokered JWT
- For self-mint and brokered re-issue JWKS discovery, the plugin exports the current public key material and operators publish the JWKS to an OCI-reachable HTTPS location
