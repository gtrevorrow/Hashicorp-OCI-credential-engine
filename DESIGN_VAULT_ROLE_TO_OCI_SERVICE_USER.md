# Design Plan: Templated Self-Mint Claims From Trusted Vault Context

## Goal
Allow operators to derive additional claims for plugin-issued self-minted subject tokens from trusted Vault context using constrained templates, so they can condense values such as alias metadata, entity metadata, group membership, or AWS auth-derived identity attributes into OCI-facing claims without promoting caller-supplied request fields into trust claims.

This document is written as implementation context for future development.

## Problem Statement
Today the plugin supports two additive claim layers for self-minted subject tokens:

1. Built-in trusted self-mint claims derived from Vault runtime context.
2. Role-scoped `self_mint_custom_claims`, which are literal JSON values appended after the trusted claim set.

That is useful for static claim injection, but it does not help when operators need to derive claim values from trusted Vault context already available to the plugin. Examples:

- copy an AWS auth alias ARN from Vault alias metadata into a concise claim such as `aws_arn`
- condense multiple trusted Vault values into a normalized subject such as `principal = aws/{{ vault.alias.metadata.arn }}`
- map group membership into a single string-valued claim for OCI trust rules
- copy selected entity metadata into OCI-facing claims without exposing the full `vault_entity_metadata` map

The current literal `self_mint_custom_claims` field cannot do that because it stores values as-is and performs no interpolation or transformation.

## Design Decision
Add a new role-level configuration field for templated self-mint claims sourced from trusted Vault context:

- keep existing `self_mint_custom_claims` unchanged for backward compatibility
- add a new field such as `self_mint_custom_claim_templates`
- render these templates during self-mint claim construction after trusted Vault context has been resolved
- expose only explicitly approved trusted namespaces to the template renderer
- keep the templating language intentionally narrow and fail closed

This feature should apply to plugin-issued self-mint flows, including:

- plugin-issued runtime token mode when the plugin self-mints because Vault identity token generation is unavailable
- brokered mode after the plugin has validated the external token and is assembling the brokered self-minted JWT

## Non-Goals
- changing the meaning of existing `self_mint_custom_claims`
- introducing arbitrary scripting or a general-purpose expression language
- allowing templates to read directly from untrusted request body inputs
- allowing templated claims to override reserved JWT claims or trusted `vault_*` claims
- introducing broad auth-method-specific special cases where existing alias/entity metadata already carries the needed values

## Current State
Current self-mint claim assembly order is:

1. standard JWT self-mint claims:
   - `iss`, `sub`, `aud`, `iat`, `exp`, `jti`
2. trusted Vault request and identity claims:
   - `vault_entity_id`
   - `vault_entity_name`
   - `vault_namespace_id`
   - `vault_entity_metadata`
   - `vault_display_name`
   - `vault_mount_accessor`
   - `vault_mount_type`
   - `vault_client_token_accessor`
   - `vault_alias_name`
   - `vault_alias_mount_accessor`
   - `vault_alias_mount_type`
   - `vault_alias_metadata`
   - `vault_alias_custom_metadata`
   - `vault_group_names`
3. brokered mapped claims when brokered mode is active
4. role-scoped literal `self_mint_custom_claims`

Current behavior of `self_mint_custom_claims`:

- stored as `map[string]interface{}`
- literal only, no interpolation
- additive only
- cannot override reserved JWT claims
- cannot use the `vault_*` namespace

## Proposed Configuration Model
Add a new role-level field:

- `self_mint_custom_claim_templates`
  - JSON object of output claim name -> string template
  - optional
  - rendered during self-mint claim construction

Keep the existing field:

- `self_mint_custom_claims`
  - JSON object of literal additive claims
  - unchanged behavior

Representative role config:

```json
{
  "self_mint_custom_claims": {
    "static_env": "prod"
  },
  "self_mint_custom_claim_templates": {
    "aws_arn": "{{ vault.alias.metadata.arn }}",
    "principal": "aws/{{ vault.alias.metadata.arn }}",
    "entity_ref": "{{ vault.entity.id }}"
  }
}
```

## Why A New Field Instead Of Reusing `self_mint_custom_claims`
Reusing `self_mint_custom_claims` for templates would create avoidable problems:

- existing roles already depend on literal JSON semantics
- changing meaning would be a breaking behavior change
- templated claims need different validation rules and failure behavior
- keeping literals and templates separate preserves operator clarity

Recommended outcome:

- `self_mint_custom_claims` remains literal and additive
- `self_mint_custom_claim_templates` is the templated additive layer

## Template Context
Templates should read from trusted context only.

Recommended namespaces:

- `vault.entity.*`
- `vault.alias.*`
- `vault.request.*`
- `vault.groups`

When brokered mode is active, a separate brokered namespace can optionally be exposed:

- `brokered.claims.*`

### Proposed Vault Template Context

`vault.entity`
- `vault.entity.id`
- `vault.entity.name`
- `vault.entity.namespace_id`
- `vault.entity.metadata.*`

`vault.alias`
- `vault.alias.name`
- `vault.alias.mount_accessor`
- `vault.alias.mount_type`
- `vault.alias.metadata.*`
- `vault.alias.custom_metadata.*`

`vault.request`
- `vault.request.display_name`
- `vault.request.mount_accessor`
- `vault.request.mount_type`
- `vault.request.client_token_accessor`

`vault.groups`
- list of group names associated with the entity, equivalent in content to `vault_group_names`

### Brokered Namespace (Optional Extension)
When brokered mode is active and the implementation wants to support mixed trusted context rendering, expose:

- `brokered.claims.sub`
- `brokered.claims.<nested-path>`

This should be a separate namespace from `vault.*` to avoid ambiguity over trust source.

## Template Language
The safest initial scope is the same narrow style used in brokered claim mappings:

- string templates only
- dotted path lookups
- literal text around interpolations

Examples:

- `{{ vault.entity.id }}`
- `{{ vault.alias.metadata.arn }}`
- `aws/{{ vault.alias.metadata.arn }}`
- `{{ brokered.claims.sub }}`

### Missing Capability: Arrays
Trusted Vault context includes values that are naturally arrays, especially:

- group names

Plain string interpolation is not enough if operators want to condense an array into a single claim. To support that safely, add a very small helper surface instead of implicit magic.

Recommended minimum helper:

- `join(list, separator)`

Examples:

- `{{ join(vault.groups, ",") }}`
- `groups/{{ join(vault.groups, "|") }}`

Explicitly defer all other helpers unless a real need appears:

- `lower()`
- `upper()`
- conditionals
- loops
- arithmetic
- scripting

## Rendering Rules
Templates should:

- fail closed on invalid syntax
- fail closed on missing references
- fail closed on type mismatches
- reject collisions with reserved JWT claims
- reject collisions with trusted `vault_*` claims
- reject collisions with earlier assembled claims

Scalar interpolation rules:

- strings interpolate directly
- booleans may stringify to `true` / `false`
- numeric values may stringify in canonical decimal form
- arrays and maps must not stringify implicitly
- arrays require explicit helper handling such as `join(...)`

## Claim Assembly Order
Recommended final order:

1. standard self-mint JWT claims
2. trusted built-in Vault claims
3. brokered mapped claims, when brokered mode is active
4. role-scoped templated self-mint claims
5. role-scoped literal `self_mint_custom_claims`

If any later layer collides with an earlier layer, fail closed.

Why put templated claims before literal claims:

- it keeps literal `self_mint_custom_claims` as the final additive operator-controlled override-free layer
- it preserves a simple mental model: computed claims first, static literals second

An equally valid alternative is to reverse 4 and 5, but the precedence must be explicit and tested.

## Security Model
This feature is safe only if the template input surface remains constrained to trusted data.

Trusted sources:

- Vault entity information returned by the system view
- Vault alias information returned by the system view
- Vault group information returned by the system view
- request context already used for trusted self-mint claims
- brokered validated claims, but only after signature and claim validation have succeeded

Untrusted sources that should not be exposed directly:

- raw request body fields
- caller-selected role name as a trust-bearing identity input
- unsigned or merely decoded caller JWT payloads

Important principle:

- this feature should condense or normalize trusted context already available to the plugin
- it should not become a path for promoting caller-controlled inputs into OCI trust claims

## AWS Auth Example
One motivating use case is AWS auth where the useful identity attribute may already be in alias metadata.

Example template config:

```json
{
  "self_mint_custom_claim_templates": {
    "aws_arn": "{{ vault.alias.metadata.arn }}",
    "principal": "aws/{{ vault.alias.metadata.arn }}"
  }
}
```

This avoids special-casing AWS in the design if the Vault alias metadata already carries the trusted ARN.

If some auth methods expose useful values only through metadata maps, the template namespace should make those maps addressable rather than adding auth-method-specific code branches.

## OCI Mapping Use Cases
This feature is useful when OCI trust rules want:

- a single normalized principal string
- a compact claim copied from trusted alias metadata
- a joined group-membership claim
- a stable entity-based reference claim

Examples:

- `principal = "entity/{{ vault.entity.id }}"`
- `aws_arn = "{{ vault.alias.metadata.arn }}"`
- `groups_csv = "{{ join(vault.groups, ",") }}"`

## Implementation Outline
### Role Schema
Update `path_roles.go`:

- add `self_mint_custom_claim_templates` field
- parse as JSON object of string -> string
- validate claim names using the same reserved-claim and `vault_*` rejection rules
- validate template syntax on write if possible

### Rendering Component
Add a new helper file, likely something like:

- `subject_token_self_mint_templates.go`

Responsibilities:

- build the trusted rendering context
- parse and render templates
- apply minimal helper functions such as `join`
- return additive rendered claims

### Claim Builder Changes
Update self-mint assembly:

- runtime self-mint path
- brokered self-mint path

New flow:

1. build standard self-mint claims
2. add trusted Vault claims
3. add brokered mapped claims when active
4. render role-scoped templated claims
5. add role-scoped literal custom claims

### Read Path
Update role read responses so `self_mint_custom_claim_templates` is visible on `read oci/role/<name>`.

## Tests
### Role Config Tests
- valid template config
- malformed JSON
- reserved output claim rejection
- `vault_*` output claim rejection
- invalid template syntax

### Template Rendering Tests
- simple scalar lookup
- nested metadata lookup
- concatenation of literals and references
- missing value failure
- non-scalar interpolation failure
- `join(vault.groups, ",")` success
- `join()` type mismatch failure

### Self-Mint Assembly Tests
- templated claims appear in runtime self-mint flow
- templated claims appear in brokered self-mint flow when enabled
- literal custom claims still work unchanged
- collisions between templated claims and trusted claims fail
- collisions between templated claims and literal custom claims fail

## Acceptance Criteria
- operators can define templated additive claims from trusted Vault context
- existing `self_mint_custom_claims` behavior remains backward compatible
- templated claims never override reserved or trusted built-in claims
- array condensation is supported only through explicit minimal helpers
- both runtime self-mint and brokered self-mint can use the feature consistently

## Risks And Mitigations
- Risk: template language grows into a scripting surface
  - Mitigation: keep syntax narrow and helper set minimal
- Risk: operators accidentally depend on unstable metadata keys
  - Mitigation: document recommended stable context paths and examples
- Risk: confusion between trusted Vault context and brokered external claims
  - Mitigation: keep separate namespaces such as `vault.*` and `brokered.claims.*`
- Risk: backward compatibility break for existing role configs
  - Mitigation: introduce a new field rather than changing `self_mint_custom_claims`

## Open Questions
- Should the first implementation include `join()` immediately, or ship scalar-only templates first and add `join()` only once needed?
- Should brokered validated claims be exposed to role templates in the first version, or should role templates start with `vault.*` only?
- Should templated claims render before or after literal `self_mint_custom_claims`, and which precedence model is easiest for operators to reason about?

## Out Of Scope
- arbitrary scripting
- conditionals and loops
- automatic per-auth-method adapters outside normal alias/entity/request metadata
- changing the semantics of existing literal `self_mint_custom_claims`
