# Design: Templated Self-Mint Claims

This document describes the implemented design. It replaces the earlier proposal for literal-only custom claims. See [README](README.md#role-scoped-custom-claims-for-self-mint) for configuration and [TEST_PLAN](TEST_PLAN.md) for evidence and live-validation gaps.

## Scope and Claim Assembly

A named `/exchange/<role>` route may contribute `self_mint_custom_claims` when the plugin signs a JWT: either the self-mint fallback after Vault identity-token generation is unavailable, or brokered re-issue after local JWT verification. Direct pass-through and successful Vault-generated plugin identity tokens are not modified by role templates.

Claims are assembled in this order:

1. Standard claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`.
2. Vault request, entity, explicitly selected linked alias, and group attributes when available.
3. Brokered mapped claims, when applicable.
4. Rendered role custom claims.

Later layers cannot replace an existing claim. Configured output names cannot be reserved JWT names (`iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `jti`) or start with `vault_`. The role name itself is not copied into a signed claim; an administrator can explicitly configure a literal such as `"oci_role":"developer"`. Such literals are operator assertions whose use must be constrained by role-path ACLs and OCI trust policy.

## Configuration and Context

`self_mint_custom_claims` is a JSON object mapping output names to string templates. Storage uses `map[string]string`; numbers, booleans, arrays and objects are not accepted as configured template values. Literal strings and interpolated strings share the same field.

| Context | Available values |
|---|---|
| `vault.entity` | `id`, `name`, `namespace_id`, `metadata.*` |
| `vault.alias` | `name`, `mount_accessor`, `mount_type`, `metadata.*`, `custom_metadata.*` |
| `vault.request` | `display_name`, `mount_accessor`, `mount_type`, `client_token_accessor` |
| `vault.groups` | List of group names; empty when no names are available |
| `brokered.claims.*` | Verified external claims, only during brokered re-issue |

Raw request-body data and merely decoded direct-flow JWT claims are not template inputs. Missing values and incompatible types fail rendering. An empty groups list can be joined to an empty string.

Example role field:

```json
{
  "self_mint_custom_claims": {
    "environment": "development",
    "entity_ref": "entity/{{ vault.entity.id }}",
    "groups_csv": "{{ join(vault.groups, \",\") }}"
  }
}
```

The JSON above is a conceptual field object; the Vault CLI field takes the serialized JSON mapping as shown in the README.

## Linked Alias Trust Boundary

Alias claims require `subject_token_identity_alias_mount_accessor` in backend configuration. Empty disables alias claims. A configured accessor must match exactly one alias on the caller's Vault entity or signing fails. There is no fallback to the first alias, mount type, or request mount.

Selected metadata describes an operator-approved linked identity, not the authentication method used to obtain the current Vault token. For example, an AWS ARN in a linked alias does not prove that this request authenticated through AWS. Another login linked to the same entity can yield the same selected alias attributes. Downstream policies must accept that trust model; current-login origin attestation is not implemented.

`vault.request.mount_*` describes the secrets engine processing the exchange. It does not select the auth alias. Existing alias-dependent templates need explicit opt-in configuration after upgrade.

## Template Grammar and Limits

Templates support literal text, dotted scalar lookups, and `join(path, separator)`. Role paths begin with `vault.` or `brokered.claims.`. `join` takes exactly two arguments: a supported path and a single- or double-quoted separator. Double-quoted separators accept Go string escapes; single-quoted separators are literal and cannot contain a single quote. Delimiter sequences `{{` and `}}` cannot be embedded in expressions or separators.

Dotted paths require nonempty segments without whitespace, control characters, braces, brackets, parentheses, quotes, commas or backslashes. There is no bracket indexing or escaping for metadata keys containing these characters or dots. Other segment characters are treated as literal key characters, not operators.

The shared parser checks the whole template independently of runtime data on config/role writes and again before rendering stored templates. A missing value cannot hide a malformed later expression. Each template is limited to 16 KiB of UTF-8 bytes; each rendered claim, including joined/interpolated text, is limited to 64 KiB. These are per-template/per-claim limits, not a total JWT size guarantee.

Strings, booleans and numeric scalar values can become strings. Objects and arrays are not implicitly serialized; role templates can join scalar list elements. Functions other than `join`, loops, conditionals and scripting are unsupported. Brokered mapping templates use a narrower grammar described in the [brokered design](DESIGN_BROKERED_SUBJECT_TOKEN_MODE.md).

## Implementation and Validation

- `claim_template.go`: complete parsing, path validation and bounded text assembly.
- `subject_token_self_mint_templates.go`: role expression evaluation and trusted context construction.
- `subject_token_callback.go` / `subject_token_broker_self_mint.go`: claims assembly and signing.
- `claim_template_test.go`: trailing errors, rejected writes preserving storage, missing runtime data, quoting and size boundaries.
- Existing template, alias and exchange tests cover rendering and signing with mocked Vault identity.

Existing malformed stored templates now fail complete parsing at runtime; repair them before exchange. Configuration writes cannot prove that future caller data contains the required fields. Real Vault multi-auth behavior, OCI claim matching, upgrade acceptance and supported deployment combinations remain separate live tests. Richer functions, non-string outputs and current-login origin attestation are not implemented.
