# Design Plan: Brokered Subject Token Mode

## Goal
Add a third explicit exchange mode where the plugin validates a caller-supplied external subject token, derives a normalized claim set from that validated token, self-mints a plugin-issued JWT, and exchanges that plugin-issued JWT with OCI.

This document is written as implementation context for future development.

## Problem Statement
Today the plugin supports two distinct subject-token modes:

1. Caller supplies a subject token and OCI validates it directly.
2. Caller omits the subject token and the plugin issues one:
   - Vault `GenerateIdentityToken` first
   - plugin self-mint when explicitly enabled and configured

Those two modes are useful, but neither provides a trust-normalization layer for external subject tokens.

In some environments, operators want:
- to accept subject tokens from IdPs or signing algorithms that OCI does not support directly
- to decouple OCI trust configuration from the exact upstream IdP
- to transform upstream claims into a smaller, stable, plugin-issued claim set
- to compose a self-minted claim from multiple upstream claims
- to avoid OCI RPST carry-over limits by collapsing multiple upstream attributes into one plugin-issued claim

## Design Decision
Add a new explicit mode:

- caller supplies an external subject token
- plugin validates that token locally against configured trust
- plugin maps validated incoming claims into a new self-minted JWT claim set
- plugin exchanges the self-minted JWT with OCI
- OCI trusts only the plugin-issued JWT for this mode

This is an identity-broker mode. It is intentionally separate from both direct pass-through and Vault-runtime self-mint.

## Supported Modes
The plugin should keep three explicit and operator-visible modes:

1. Direct caller-supplied token mode
- Caller provides `subject_token`
- Plugin passes it to OCI
- OCI validates the token and applies trust rules

2. Plugin-issued runtime token mode
- Caller omits `subject_token`
- Plugin resolves subject token from Vault runtime context
- Vault identity token first, then self-mint when configured

3. Brokered external token mode
- Caller provides `subject_token`
- Plugin validates the token locally
- Plugin re-issues a self-minted JWT from validated claims
- OCI trusts the plugin-issued JWT, not the original external token

These modes must not blur together implicitly. Operators need to know which issuer OCI is trusting.

## Non-Goals
- Silent auto-detection between direct pass-through and brokered mode
- Replacing the existing direct caller-supplied exchange flow
- General scripting or arbitrary code execution in claim mapping
- Allowing mapped claims to override reserved JWT claims
- Allowing mapped claims to override trusted `vault_*` claims
- Supporting every possible JWT trust mechanism in the first release

## Trust Model
In brokered mode, the plugin becomes the JWT validation authority for the incoming external subject token.

That means the plugin must validate, at minimum:
- issuer
- signature
- signing key / JWKS
- allowed algorithms
- audience
- expiration and not-before
- optional clock skew

The plugin then becomes the issuer of record for the token OCI sees.

This is different from the current direct caller-supplied mode, where OCI remains the validation authority.

The first implementation should explicitly support incoming JWTs signed with:
- RSA
- elliptic-curve algorithms

## High-Level Flow
1. Caller authenticates to Vault and obtains a Vault token.
2. Caller submits an external `subject_token` to the plugin.
3. Plugin identifies that brokered mode is enabled for this request/backend.
4. Plugin validates the external token against local trust config.
5. Plugin optionally derives a plugin role from validated incoming claims.
6. Plugin builds a new self-minted JWT:
   - trusted base claims
   - mapped claims from the validated external token
   - optional role-scoped additive self-mint custom claims
7. Plugin exchanges the self-minted JWT with OCI.
8. OCI validates only the plugin issuer and trust rules for the self-minted JWT.
9. OCI returns UPST or RPST.

## Claim Source Layers
Brokered self-mint should assemble claims in layers, with strict precedence:

1. Reserved JWT claims
- `iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `jti`
- always controlled by plugin self-mint logic

2. Trusted plugin/Vault claims
- current `vault_*` namespace claims
- remain non-overridable

3. Mapped claims from validated external token
- produced from mapping rules / templates
- may add new claims only

4. Role-scoped additive custom claims
- existing `self_mint_custom_claims`
- still additive only
- still cannot override reserved or trusted claims

If any later layer conflicts with an earlier layer, fail closed.

## Role Selection
Role selection should remain a separate concern from claim construction.

Recommended order:
1. Validate incoming external token.
2. Optionally derive plugin role from validated incoming claims.
3. Load role-scoped policy and additive claim config.
4. Build brokered self-minted JWT.

This keeps:
- trust validation
- role selection
- claim transformation
as distinct stages.

## Configuration Model
The first release should use explicit brokered-mode config, not implicit reuse of existing pass-through settings.

Representative backend config shape:

- `brokered_subject_token_enabled`
  - bool
  - enables the new mode

- `brokered_subject_token_trust`
  - structured trust config for validating incoming external JWTs
  - includes issuer, audience, alg allowlist, trust source, and skew

- `brokered_subject_token_claim_mappings`
  - JSON object or ordered mapping rules
  - defines how validated incoming claims become self-minted claims

- `brokered_subject_token_role_mappings`
  - optional role derivation from validated external claims
  - separate from output-claim construction

- `brokered_subject_token_default_audience`
  - optional self-mint audience override for this mode if it must differ from the normal self-mint audience

Representative role-level config shape:
- existing `self_mint_custom_claims`
  - continues to apply additively after brokered claim mapping

## Validation Configuration
The first release should support one clear trust source at a time per backend, not every variation.

Recommended initial support:
- single issuer
- explicit trust source
- explicit allowed algorithms
- explicit allowed audiences
- bounded clock skew

Recommended trust-source options:
- OIDC discovery
  - plugin resolves issuer metadata and JWKS URI from the issuer
  - operationally simple when the issuer publishes standard discovery metadata
- explicit JWKS URL
  - operator provides the JWKS endpoint directly
  - requires network reachability from the plugin runtime to that endpoint
- direct JWKS document upload
  - operator stores trusted verification keys directly in plugin config
  - avoids runtime dependency on external network access
- direct public-key upload
  - operator stores one or more public keys directly in plugin config
  - useful when upstream key rotation is manual or tightly controlled

Operational note:
- OIDC discovery and explicit JWKS URL modes may require the Vault plugin runtime to reach the public internet or a routed private network path to the issuer.
- Direct JWKS or public-key upload modes reduce that runtime dependency, but shift more rotation responsibility to operators.

Defer for later:
- multiple issuers per backend
- automatic issuer discovery
- complex key-source fallback chains

## Library Selection Requirement
JWT, JWK, and JWKS handling in brokered mode is security-sensitive.

Implementation should prefer mature, well-maintained libraries over custom parsing or crypto glue.

Requirements:
- use established Go libraries for JWT verification and JWKS key resolution
- avoid bespoke crypto implementation
- avoid handwritten JOSE/JWK parsing when a well-maintained library already covers the use case
- validate that the chosen library supports both RSA and elliptic-curve verification cleanly
- prefer libraries with a strong maintenance history and a low history of security issues

Selection criteria should include:
- active maintenance
- clear support for issuer/audience/signature validation
- clean JWKS refresh behavior
- support for RSA and EC algorithms
- low complexity of the integration surface

## Mapping DSL
The mapping language should be intentionally narrow in the first release.

### First Release Scope
Support only string-template-based output construction.

Capabilities:
- direct claim reference
- string interpolation
- concatenation of multiple incoming claims and literals
- nested claim access
- static string literals

Examples:
- `employee_id = "{{ claims.employee.id }}"`
- `principal = "{{ claims.tenant }}:{{ claims.department }}:{{ claims.user }}"`
- `rpst_subject = "svc/{{ claims.org }}/{{ claims.app }}/{{ claims.env }}"`

### Explicitly Deferred
- function library such as `lower()`, `upper()`, `coalesce()`
- arithmetic
- arbitrary conditionals
- loops
- embedded scripting

Those can be added later only if a real need appears.

## Mapping Constraints
Mapped claims must follow these rules:
- may only read from validated incoming claims
- may only produce new, additive claims
- may not override reserved JWT claims
- may not override trusted `vault_*` claims
- may not override already-produced mapped claims
- must fail closed on missing required inputs, invalid templates, or type mismatches

The result should be deterministic and reviewable by operators.

## Operational Benefits
This mode gives operators:
- a stable plugin-issued trust surface for OCI
- flexibility to onboard new upstream subject-token providers
- insulation from OCI limitations on upstream JWT formats or algorithms
- a clean place to collapse multiple upstream claims into a smaller OCI-facing claim set

## Security Risks and Mitigations
### Risk: plugin becomes a JWT broker
- Mitigation: keep brokered mode explicit and separately configured

### Risk: misconfigured trust accepts untrusted external tokens
- Mitigation: require explicit issuer, audience, alg, and key config

### Risk: mapping logic becomes too powerful
- Mitigation: start with string templates only

### Risk: claim confusion between upstream claims and trusted local claims
- Mitigation: preserve reserved claim denylist and trusted `vault_*` boundary

### Risk: role derivation and claim mapping become coupled
- Mitigation: keep role selection and output-claim mapping in separate config sections

## Example End-to-End Use Case
1. External IdP issues JWT with:
- `tenant=acme`
- `division=platform`
- `workload=deploy-bot`

2. Plugin validates that JWT locally.

3. Plugin mapping produces:
- `oci_principal = "acme/platform/deploy-bot"`

4. Plugin self-mints JWT containing:
- normal reserved self-mint claims
- trusted `vault_*` claims
- `oci_principal`

5. OCI trust rules match `oci_principal` and issue RPST/UPST.

This allows three upstream claims to collapse into one OCI-facing claim.

## Recommended Incremental Delivery
### Phase 1
- design and config model
- explicit mode toggle
- incoming JWT validation
- string-template claim mapping
- additive claim merge with collision rejection
- unit tests for trust and mapping

### Phase 2
- role derivation from validated external claims
- docs and sequence diagrams
- OCI sandbox end-to-end tests

### Phase 3
- carefully chosen template helpers such as normalization functions if justified

## Acceptance Criteria
- Brokered mode is explicit and independently configurable.
- The plugin validates incoming external subject tokens locally before re-issuing.
- Mapped claims are additive only.
- Reserved JWT claims and trusted `vault_*` claims remain non-overridable.
- Operators can compose one output claim from multiple incoming claims using string templates.
- OCI can trust only the plugin-issued JWT for this mode.

## Open Questions
- Should brokered mode require a separate self-mint issuer/audience from the existing self-mint mode, or reuse it by default?
- Should role derivation in brokered mode reuse `subject_token_role_mappings` semantics or have a separate config block to avoid ambiguity?
- Should missing claims in a template always fail, or should there be an explicit optional-field syntax in a later phase?
- Should brokered mode be enabled per backend only, or also overridable per role?

## Out of Scope For First Release
- Multiple upstream issuers per backend
- Rich function DSL
- General-purpose policy language
- Automatic migration of existing direct caller-supplied flows into brokered mode
