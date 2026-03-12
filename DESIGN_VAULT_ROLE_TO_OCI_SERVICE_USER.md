# Design Plan: Vault Role to OCI Service User Mapping

## Goal
Map a Vault-authenticated workload to an OCI Domain Service User through OCI Token Exchange Trust rules, without duplicating JWT validation logic already performed by OCI Identity Domains.

This document is written as implementation context for LLM-assisted development.

## Design Decision
- Keep this plugin focused on token exchange.
- Keep plugin-issued JWT behavior as optional fallback mode, not the primary design.
- Use Vault Identity Tokens (`identity/oidc/token/<role>`) as the subject token source when role/claim-based mapping is needed.
- Let OCI Identity Domains remain the JWT validation authority (issuer trust, JWKS, claim evaluation).

## Current State (in this repo)
- `oci/exchange` supports:
  - caller-supplied `subject_token`
  - callback fallback when `subject_token` is omitted:
    - tries Vault `GenerateIdentityToken` first
    - optional plugin self-mint fallback (RSA-signed JWT) when configured
  - plugin `role` for local TTL/policy behavior only
- In self-mint fallback mode, plugin can inject configured role claim into fallback JWT when request includes `role`.
- No local JWT signature validation is performed by this plugin.
- `oci/jwks` endpoint exposes JWKS derived from self-mint signing key for OCI trust bootstrap.

## Target End-to-End Flow
1. Workload authenticates to Vault (Kubernetes/JWT/AppRole/etc.).
2. Workload receives a Vault token tied to a Vault entity.
3. Workload mints a Vault identity token from a specific Vault OIDC role:
   - endpoint: `identity/oidc/token/<vault_oidc_role>`
   - token includes role-specific claims (for OCI trust mapping).
4. Workload calls this plugin:
   - `vault write oci/exchange subject_token=<vault_identity_jwt> role=<plugin_role>`
5. Plugin exchanges subject token with OCI Domain token endpoint.
6. OCI evaluates Token Exchange Trust:
   - verifies Vault issuer/JWKS and required claims
   - maps claim pattern to target OCI Domain Service User
7. OCI returns UPST/RPST for that mapped OCI principal.
8. OCI IAM policies on the mapped Service User govern authorization.

## Claim Mapping Strategy
Use a stable claim dedicated to OCI mapping, for example:
- `oci_target`: direct service-user routing value (`svc-dev-automation`)
- or `vault_role`: abstract role value (`developer`) mapped by OCI trust rules

Recommended: `oci_target` for explicitness and lower ambiguity.

## Vault Configuration Model
### 1) OIDC issuer and key
- Configure `identity/oidc/config` issuer.
- Create signing key under `identity/oidc/key/<key_name>`.

### 2) One or more OIDC roles for token minting
- Create `identity/oidc/role/<role_name>`.
- Set:
  - `key`
  - `client_id` (expected audience for OCI trust)
  - short `ttl`
  - claim template containing `oci_target` (or `vault_role`) and optional metadata

### 3) Vault policy
- Grant callers `read` on `identity/oidc/token/<role_name>`.
- Grant callers access to `oci/exchange`.

## OCI Configuration Model (Conceptual)
In OCI Identity Domain Token Exchange Trust configuration:
- Trust Vault issuer and JWKS.
- Require expected `aud`.
- Match claim value:
  - example: `oci_target == "svc-dev-automation"`
- Map match to OCI Domain Service User.

Then attach OCI IAM policies to that Service User.

## Plugin Scope and Required Changes
### Keep
- Current exchange behavior and OCI as the validation authority.
- Existing role-based TTL controls.

### Add (recommended, minimal)
- Documentation for the Vault-issued subject token flow (this design).
- Optional guardrail: enforce that plugin request `role` is consistent with a claim value in the supplied JWT (string match only).
  - This is a consistency control, not signature validation.
  - If implemented, parse JWT payload only and compare claim to requested role.
- Optional self-mint fallback controls:
  - auto-generate RSA signing key if missing
  - expose public key as JWKS for OCI trust

### Do Not Add
- Local JWKS caching/validation in plugin.
- Plugin-issued JWTs/JWKS as mandatory default mode.

## Data/Control Mapping
- Vault auth role/entity -> determines who can mint which OIDC token role.
- Vault OIDC role -> determines claim set (`oci_target` or `vault_role`).
- OCI trust rule -> maps claim pattern to OCI Service User.
- Plugin `role` -> local lease/TTL constraints and optional consistency guardrail.

## Example Naming Convention
- Vault OIDC roles:
  - `oci-dev`
  - `oci-prod`
- Claim values:
  - `oci_target=svc-dev-automation`
  - `oci_target=svc-prod-automation`
- Plugin roles:
  - `developer`
  - `production`

## Implementation Backlog
1. Documentation
- Add a new README section for "Vault-issued subject token flow".
- Include required Vault and OCI config prerequisites.

2. Optional plugin guardrail
- Add config toggle and claim key:
  - `enforce_role_claim_match` (bool)
  - `role_claim_key` (default `vault_role` or `oci_target`)
- In `path_exchange.go`:
  - if enabled, compare claim vs request `role` using the effective subject token (caller-provided or fallback-generated).
  - fail with clear error on mismatch.

3. Callback and JWKS operational controls
- Add and document `oci/jwks` endpoint for OCI trust setup.
- Ensure self-mint key generation/rotation procedures are documented.

4. Tests
- Unit tests for guardrail logic:
  - match success
  - mismatch failure
  - missing claim failure
  - disabled toggle bypass
- No local signature validation tests needed.

5. Operational validation
- Run end-to-end test with OCI sandbox:
  - token minted from Vault OIDC role
  - successful mapping to expected OCI Service User
  - verify resulting permissions align with policy.

## Acceptance Criteria
- A client can mint a Vault identity token and exchange it through this plugin.
- OCI maps token claims to the intended Service User.
- Resulting OCI token permissions match expected policies.
- Plugin remains stateless for JWT trust validation (delegated to OCI).

## Risks and Mitigations
- Risk: claim drift between Vault templates and OCI trust rules.
  - Mitigation: centralize claim key names and naming conventions.
- Risk: overly broad OCI trust conditions.
  - Mitigation: strict `iss`, `aud`, and exact claim matching.
- Risk: role confusion between plugin role and identity token role.
  - Mitigation: explicit docs and optional role-claim consistency check.

## Out of Scope (for this phase)
- Building a new plugin to mint subject tokens.
- Replacing OCI trust evaluation with local plugin validation.
- Full custom IdP behavior inside this exchange plugin.
