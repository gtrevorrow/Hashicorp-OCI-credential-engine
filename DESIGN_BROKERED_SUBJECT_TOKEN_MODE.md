# Design: Brokered Subject Token Mode

This document describes the implemented brokered mode and its deliberate limits. Earlier proposals for brokered role mappings, nested trust configuration and a separate brokered output audience were not implemented.

## Mode Selection

| Request and configuration | Behavior |
|---|---|
| Caller supplies `subject_token`; brokered mode disabled | Original token passes to OCI for validation. Optional direct `subject_token_role_mappings` reads decoded claims; it does not locally authenticate the JWT. |
| Caller supplies `subject_token`; brokered mode enabled | Plugin verifies the external JWT, maps verified claims, signs a replacement JWT and sends that replacement to OCI. |
| Caller omits `subject_token`; plugin-issued mode enabled | Default callback tries Vault `GenerateIdentityToken`, then self-mints only if explicitly enabled and configured. |
| Caller omits token; plugin-issued mode disabled | Request fails. An explicitly empty token also fails rather than choosing fallback. |

Mode selection is configured per backend mount, not per role. `subject_token_audience` is a plugin-issued-mode override and is rejected with caller-supplied tokens. Brokered re-issue uses `subject_token_self_mint_audience`.

## Trust and Configuration

Brokered mode requires `brokered_subject_token_enabled=true`, a trust type, issuer, nonempty audience and algorithm allowlists, and the trust material required by the selected source. It also requires `subject_token_self_mint_issuer`; a signing key is generated when omitted. The self-mint enabled flag is not required for brokered signing, but the current `/jwks` export endpoint still requires it.

The implemented fields are flat:

- `brokered_subject_token_trust_type`: `oidc_discovery`, `jwks_url`, `jwks_json`, or `public_keys`.
- `brokered_subject_token_issuer`, `brokered_subject_token_allowed_audiences`, `brokered_subject_token_allowed_algs`, `brokered_subject_token_clock_skew_seconds`.
- `brokered_subject_token_jwks_url`, `brokered_subject_token_jwks_json`, or `brokered_subject_token_public_keys` as applicable.
- `brokered_subject_token_claim_mappings`: JSON object of output claim names to string templates.
- `brokered_subject_token_allowed_jwks_origins` and `debug_allow_brokered_http`: remote retrieval policy.

There are no `brokered_subject_token_trust`, `brokered_subject_token_role_mappings`, or `brokered_subject_token_default_audience` fields. Shared `subject_token_self_mint_*` fields configure the replacement JWT. See the [README parameter reference](README.md#oci-federated-identity-setup).

Incoming signatures use go-jose with configured RSA (`RS256/384/512`) or EC (`ES256/384/512`) algorithms and suitable public signing keys. Validation checks issuer, allowed audience, required expiration, and `nbf`/`iat` when supplied, with configured skew. The plugin has no persistent one-time-use replay tracking.

Remote retrieval requires HTTPS, exact discovery issuer matching, approved discovered-JWKS origins, checked public destination addresses, and no redirects or environment proxies. Only explicit loopback debug mode allows HTTP/local destinations. Private-network IdPs need managed inline keys in this version. Documents and brokered JWTs are bounded to 1 MiB and key sets to 64 keys. Remote keys are cached for five minutes with coordinated refresh and a 30-second refresh/failure cooldown. Refresh failures fail closed; removal of a cached key is not immediate revocation. See [remote trust and rotation](README.md#brokered-remote-trust-and-key-rotation).

## Role Selection and Claim Assembly

Brokered mode does not reuse direct `subject_token_role_mappings` and does not derive a role from external claims. An explicit `/exchange/<role>` path selects the role for TTL policy and additive `self_mint_custom_claims`; bare `/exchange` has no role contribution. A body `role` is rejected by strict exchange schema validation.

After verifying the incoming token, the plugin renders `brokered_subject_token_claim_mappings` from `claims.*`. Replacement JWT assembly uses standard claims, Vault identity context, mapped external claims, then optional role claims. Reserved JWT names and the `vault_*` namespace are protected; collisions fail. The standard replacement `sub` is derived from Vault context, not copied from the upstream token. Map upstream `sub` to a separate claim such as `external_sub` when needed.

Linked alias claims require explicit auth accessor configuration and are not evidence of the current login method. See [self-mint claim design](DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md#linked-alias-trust-boundary).

## Mapping Language

Brokered mappings support literal strings and dotted scalar lookups from verified external claims:

```json
{
  "external_sub": "{{ claims.sub }}",
  "principal": "svc/{{ claims.org }}/{{ claims.user.id }}"
}
```

This layer supports no functions, including `join`. Role templates may separately use `vault.*`, `brokered.claims.*`, and `join` during brokered signing. All mapped outputs are strings; missing values, nulls, objects and arrays fail scalar interpolation.

Complete syntax is checked before any lookup, both on writes and at runtime. Each template is limited to 16 KiB and each rendered claim to 64 KiB, measured in bytes. Invalid trailing expressions cannot be hidden by missing earlier data. Dotted-path and delimiter rules are shared with [role templates](DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md#template-grammar-and-limits).

## OCI and Operational Boundary

OCI validates the replacement JWT against trust for the plugin issuer/key and determines final OCI identity and permissions. Operators publish the plugin's public JWKS to an OCI-reachable HTTPS endpoint; Vault's authenticated `/jwks` endpoint is an export, not a public discovery service. Plugin signing-key rotation and overlapping multi-key publication remain unimplemented.

The chosen role/backend/Vault TTL ceilings bound RPST `rpst_exp` and the Vault lease. Returned OCI expiry, when known, can further shorten that lease. Vault leases are nonrenewable and their revocation does not revoke the upstream OCI credential.

Tests cover verification, remote-trust policy, mappings, collisions, templates and mock OCI exchange. Real IdP/Vault/OCI acceptance, key rollover, deployment networking and FIPS validation remain outstanding; see [TEST_PLAN](TEST_PLAN.md). Multiple issuers, brokered role derivation, richer functions, per-role mode overrides and stateful replay controls remain future work, not supported configuration.
