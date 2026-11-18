# Usage and API Reference

[README](../README.md) · [Mapping overview](../README.md#mapping-features) · [Operator configuration](configuration.md)

Examples use illustrative tokens and keys. For real credentials, use owner-only request files or stdin and protect exchange responses as shown in [Using Returned Credentials with OCI Clients](#using-returned-credentials-with-oci-clients).

## Exchange a JWT for OCI Credentials

```bash
vault write oci/exchange/developer \
    subject_token="eyJhbGciOiJSUzI1NiIs..." \
    requested_token_type="urn:oci:token-type:oci-upst" \
    ttl=3600
```

Notes:

- Omit `subject_token` and set `enable_plugin_issued_subject_token=true` if you want the credential engine to obtain one on the caller's behalf. On Vault Enterprise, the engine first tries Vault identity-token generation. On Vault Open Source, or if Vault cannot generate an identity token for the request, the engine can fall back to self-mint when `subject_token_self_mint_enabled=true` and the required self-mint settings are configured.
- If the credential engine obtains a subject token on the caller's behalf, the caller may optionally provide `subject_token_audience`. A nonempty override is trimmed, validated using the same 512-byte and control-character rules, and accepted only when its normalized value is listed in `subject_token_allowed_audiences`. Whitespace-only overrides are rejected; omitted or empty-string overrides retain the configured default. These rules apply to plugin-issued tokens, not the incoming brokered JWT audience allowlist.
- Exchange requests reject fields outside the endpoint schema before token resolution, validation, or signing. Bare `oci/exchange` does not accept a `role` body field.
- Use `oci/exchange/<role>` when you want Vault policy to control which plugin role may be used for the exchange.
- Use bare `oci/exchange` when `subject_token_role_mappings` are configured and the engine should derive the effective Vault role from decoded JWT claims that OCI must authenticate.
- If `public_key` is not supplied, the engine generates a fresh RSA key pair for the exchange and returns only the generated `private_key`.

*Reference: Oracle JWT-to-UPST flow and request parameters are documented in [Token Exchange Grant Type: Exchanging a JSON Web Token for a UPST](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm#jwt_token_exchange__get-oci-upst).*

**Response:**
```json
{
  "data": {
    "access_token": "eyJ...",
    "session_token": "eyJ...",
    "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE...",
    "requested_token_type": "urn:oci:token-type:oci-upst",
    "token_type": "Bearer",
    "credential_expiry_known": true,
    "expires_in": 3600,
    "expires_at": "2024-01-15T10:30:00Z"
  },
  "lease_id": "oci/exchange/...",
  "lease_duration": 3600,
  "renewable": false
}
```

<a id="response-private-key"></a>
The `private_key` response field contains the generated PEM-encoded exchange private key, used to sign OCI API requests with the returned session token. It is present only when the engine generates the exchange keypair. If the caller supplies `public_key`, the response contains neither `private_key` nor `public_key`; the caller retains its own matching private key. This applies to all exchange modes. See [session tokens and request signing](#session-tokens-and-request-signing).

## Caller-Supplied Subject Token Flow (JWT Claim to Vault Role Mapping)

Use this flow when callers supply their own JWTs and the plugin should select the effective role from decoded JWT claims before OCI validates the original token. Local mapping alone is not authentication.

1. Configure ordered subject-token role mappings:

```bash
vault write oci/config \
    domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..xxxxx" \
    client_secret="<oauth-client-secret>" \
    default_ttl=3600 \
    max_ttl=28800 \
    subject_token_role_mappings='[
      {"claim":"vault_role","op":"eq","value":"developer","role":"developer"},
      {"claim":"groups","op":"co","value":"ops","role":"operations"}
    ]'
```

2. Ensure the upstream JWT issuer emits the claim values you want to match.

Rule semantics:

- Rules are evaluated in order.
- The first matching rule wins.
- Supported operators are `eq` (equals), `co` (contains), and `sw` (starts with).
- Matching works with string claims and array-of-string claims.
- When `subject_token_role_mappings` is configured, callers should use bare `oci/exchange`; the plugin derives the effective role from the JWT instead of accepting a role-specific exchange path.
- If no rule matches, the exchange is rejected.

Example mapping behavior:

```json
[
  {"claim":"vault_role","op":"eq","value":"developer","role":"developer"},
  {"claim":"groups","op":"co","value":"ops","role":"operations"},
  {"claim":"sub","op":"sw","value":"svc:","role":"service"}
]
```

If the caller-supplied JWT contains:

```json
{
  "vault_role": "developer",
  "groups": ["team-ops", "team-dev"],
  "sub": "svc:deploy"
}
```

then the effective Vault role is `developer`, because the first rule already matches and later rules are not evaluated.

Example using Vault's built-in Identity/OIDC issuer as the upstream JWT source:

This example is not configuring this plugin to mint the JWT. It is showing how Vault's native `identity/oidc/...` endpoints can act as the upstream issuer for the caller-supplied `subject_token` that is later exchanged through `oci/exchange`.

In other words:

- Vault Identity OIDC mints the JWT
- the JWT contains claims such as `vault_role`
- this plugin reads those JWT claims and derives the effective plugin role from `subject_token_role_mappings`

```bash
# Set issuer used in OIDC discovery/JWKS
vault write identity/oidc/config \
    issuer="https://vault.example.com/v1/identity/oidc"

# Create signing key
vault write identity/oidc/key/oci-subject-key \
    algorithm="RS256" \
    rotation_period="24h" \
    verification_ttl="72h" \
    allowed_client_ids="oci-token-exchange"

# Create token role that emits the claim this plugin will map to a role
vault write identity/oidc/role/oci-developer \
    key="oci-subject-key" \
    client_id="oci-token-exchange" \
    ttl="10m" \
    template='{"vault_role":"developer"}'
```

Grant workload policy access to mint this token:

```hcl
path "identity/oidc/token/oci-developer" {
  capabilities = ["read"]
}

path "oci/exchange" {
  capabilities = ["update"]
}
```

3. Workload mints a Vault identity token:

```bash
SUBJECT_TOKEN="$(vault read -field=token identity/oidc/token/oci-developer)"
```

4. Workload exchanges that token through this plugin:

```bash
vault write oci/exchange \
    subject_token="$SUBJECT_TOKEN" \
    requested_token_type="urn:oci:token-type:oci-upst"
```

## Brokered Caller-Supplied Subject Token Flow (Template-Based Claim Mapping)

Use this flow when callers still provide `subject_token`, but OCI should trust only a plugin-issued JWT. In this mode the plugin validates the incoming JWT locally, renders mapped claims from the validated external claims, self-mints a new JWT, and exchanges that brokered JWT with OCI.

1. Configure brokered mode and define the template-based claim mappings:

Required values in this example:

- `subject_token_self_mint_issuer`
  Required because the plugin re-issues a brokered JWT and must set its `iss` claim.
- `brokered_subject_token_enabled=true`
  Required to turn on brokered handling for caller-supplied `subject_token` values.
- `brokered_subject_token_trust_type="public_keys"`
  Required to tell the plugin how to validate the incoming external JWT. Supported values are `oidc_discovery`, `jwks_url`, `jwks_json`, and `public_keys`.
- `brokered_subject_token_issuer`
  Required expected `iss` claim on the incoming external JWT.
- `brokered_subject_token_allowed_audiences`
  Required non-empty allowlist for the incoming external JWT `aud` claim.
- `brokered_subject_token_allowed_algs`
  Required non-empty allowlist for the incoming external JWT signing algorithm. Supported values are RSA (`RS256`, `RS384`, `RS512`) and EC (`ES256`, `ES384`, `ES512`). In most brokered trust relationships this should be a single algorithm.
- `brokered_subject_token_public_keys`
  Required for this example because `brokered_subject_token_trust_type=public_keys`.

Optional values shown or omitted in this example:

- `brokered_subject_token_claim_mappings`
  Optional. If omitted, the plugin still validates and re-issues the JWT, but it adds no mapped external claims to the brokered token.
- `brokered_subject_token_clock_skew_seconds`
  Optional. Default is `0`, so `exp`, `nbf`, and `iat` are evaluated with no extra skew tolerance unless you set one.
- `subject_token_self_mint_audience`
  Optional. Default is `urn:mace:oci:idcs` if not supplied.
- `subject_token_self_mint_ttl_seconds`
  Optional. Default is `600` seconds if not supplied.
- `subject_token_self_mint_private_key`
  Optional. If omitted, the plugin generates and stores an RSA signing key automatically when self-mint signing is needed.

```bash
vault write oci/config \
    domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..xxxxx" \
    client_secret="<oauth-client-secret>" \
    subject_token_self_mint_issuer="https://vault.example.com" \
    brokered_subject_token_enabled=true \
    brokered_subject_token_trust_type="public_keys" \
    brokered_subject_token_issuer="https://issuer.example.com" \
    brokered_subject_token_allowed_audiences="urn:example:workload" \
    brokered_subject_token_allowed_algs="RS256" \
    brokered_subject_token_public_keys='["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"]' \
    brokered_subject_token_claim_mappings='{
      "external_sub":"{{ claims.sub }}",
      "department":"{{ claims.department }}",
      "principal":"svc/{{ claims.org }}/{{ claims.app }}/{{ claims.env }}",
      "employee_ref":"{{ claims.user.profile.employee_id }}"
    }'
```

2. The upstream JWT must be signed and have the required issuer, audience and unexpired `exp`. This abbreviated payload illustrates the mapped fields; it is not a complete valid token:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user-123",
  "aud": "urn:example:workload",
  "org": "acme",
  "app": "billing",
  "env": "prod",
  "department": "finance",
  "user": {
    "profile": {
      "employee_id": "E-4242"
    }
  }
}
```

3. With the mapping config above, the brokered self-minted JWT produced by the plugin will add these OCI-facing claims:

```json
{
  "external_sub": "user-123",
  "department": "finance",
  "principal": "svc/acme/billing/prod",
  "employee_ref": "E-4242"
}
```

The plugin also adds its normal self-mint claims such as `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, plus trusted `vault_*` claims when available. Mapped claims are additive only. They cannot override reserved JWT claims or `vault_*` claims.

4. The workload calls the normal exchange path with the external JWT:

```bash
vault write oci/exchange \
    subject_token="$EXTERNAL_SUBJECT_TOKEN" \
    requested_token_type="urn:oci:token-type:oci-upst"
```

5. If you need existing role TTL controls or additive templated `self_mint_custom_claims`, use the explicit role path:

```bash
vault write oci/exchange/developer \
    subject_token="$EXTERNAL_SUBJECT_TOKEN" \
    requested_token_type="urn:oci:token-type:oci-upst"
```

Brokered-mode mapping rules:

- Template expressions are string-only and may reference validated incoming claims such as `{{ claims.sub }}` or nested values such as `{{ claims.user.profile.employee_id }}`.
- Literal text around interpolations is allowed, for example `svc/{{ claims.org }}/{{ claims.app }}/{{ claims.env }}`.
- Missing claim references, invalid template syntax, reserved output claim names, and `vault_*` output claim names fail closed.
- Existing `subject_token_role_mappings` are not used in brokered mode. Brokered mode and direct caller-token role derivation are separate flows.

6. OCI Identity Domain token exchange trust evaluates issuer, audience, and the brokered plugin-issued claims and maps to the target OCI Domain Service User. OCI IAM policies on that service user determine final permissions.

See [DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md](../DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md) for full architecture and implementation details.

## Plugin-Issued Exchange Without an External JWT

After configuring the OCI connection, enable plugin-issued mode. If self-mint fallback is needed, also configure the engine's issuer:

```bash
vault write oci/config \
    enable_plugin_issued_subject_token=true \
    subject_token_self_mint_enabled=true \
    subject_token_self_mint_issuer="https://vault-issuer.example.com"
```

Configure OCI trust for the token issuer and claims it will receive. For engine-signed tokens, complete the [JWKS publication workflow](configuration.md#self-mint-jwks-publication-workflow).

The workload omits `subject_token`:

```bash
vault write -force oci/exchange/developer
```

The engine first asks Vault for a plugin identity token. If Vault cannot provide one, it uses self-mint only when explicitly enabled and configured; otherwise the request fails. Enabling self-mint does not override a successful Vault-generated token. Vault-generated plugin tokens have their own issuer and claims; the engine's role templates do not modify them. Configure OCI trust for whichever token source your deployment uses.

For in-plugin self-mint, identity claims come from trusted Vault runtime context. The selected exchange role is not copied into the JWT. It can apply TTL policy and add explicitly configured custom claims, as described below.

## Default Self-Mint Claim Set

When plugin-issued subject-token mode uses in-plugin self-minting, the emitted JWT uses a fixed, opinionated claim set derived from trusted Vault runtime context.

Standard JWT claims:

- `iss`
- `sub`
- `aud`
- `iat`
- `exp`
- `jti`

Vault-derived claims included when available:

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

Design notes:

- The selected exchange role is not copied into the self-minted JWT. This is intentional: the role is a local plugin control used for Vault-side constraints and optional additive custom claims, not a trusted identity fact about the caller. Keeping it out of the JWT avoids turning a caller-selected plugin input into an OCI trust claim.
- `aud` defaults to plugin config (`subject_token_self_mint_audience`) and may be overridden per request only through allowlisted `subject_token_audience` values.
- OCI trust rules should use the Vault-derived claims above rather than caller-supplied parameters.
- When the caller request is backed by a Vault Identity entity, `vault_entity_id` is the preferred stable trust-mapping claim.
- When the caller is using a token flow without an attached entity, the self-minted JWT still includes token-context claims such as `vault_display_name`, `vault_mount_accessor`, `vault_mount_type`, and `vault_client_token_accessor`, and OCI trust can map on those if needed.
- Claims like `vault_display_name` and `vault_client_token_accessor` are a weaker trust anchor than `vault_entity_id` because they identify token context rather than a durable Vault identity. Prefer `vault_entity_id` whenever it is available.

## Explicit Linked Alias Selection

`subject_token_identity_alias_mount_accessor` on `oci/config` selects the auth mount whose linked entity alias may supply `vault_alias_*` claims and `vault.alias.*` templates. It applies to in-plugin self-mint and brokered signing. The default is empty: no alias claims are emitted, even for an entity with one alias. Templates requiring missing alias data fail before signing.

To include alias claims, choose which Vault authentication method should supply them—for example, the AWS auth method mounted at `aws/`.

1. Run `vault auth list -detailed`. Find that authentication method and copy its **Accessor** value. This identifies the auth mount; it is different from its path (`aws/`).
2. Check that the caller's Vault entity has an alias for that auth mount. Confirm that your OCI trust rules should accept attributes from this linked identity, even when the caller logs in through another method linked to the same entity.
3. Set the accessor on `oci/config`. Replace `auth_aws_example` below with the value you copied:

```bash
vault write oci/config subject_token_identity_alias_mount_accessor=auth_aws_example
```

The entity must have exactly one alias with that accessor. Missing entity, missing match, and duplicate matches fail issuance. There is no fallback by mount type, alias order, or request mount. `vault_mount_*` describes the OCI secrets engine handling the request; `vault_alias_mount_*` describes the explicitly selected linked auth mount.

**Trust boundary:** This selection asserts a linked identity attribute. It does not prove that the current Vault token was authenticated through that auth method. Callers authenticating through another alias of the same entity can still receive the configured linked alias claims when permitted to exchange. If downstream authorization requires proof of a particular login method, do not use these claims as that proof; use an independently verified identity flow and appropriate Vault policies.

**Upgrade:** Automatic alias selection has been removed. Review existing alias-dependent OCI mappings and templates before upgrading. Opt in only when linked-identity trust is intended, or switch to stable entity claims. Clear the setting with `subject_token_identity_alias_mount_accessor=""` to disable alias emission. Direct token pass-through and Vault-generated plugin identity tokens are unchanged.

## Role-Scoped Custom Claims For Self-Mint

Roles may optionally contribute additional custom claims to self-minted subject tokens through string templates stored in `self_mint_custom_claims`.

Guardrails:

- This applies when an explicit role is selected and the engine signs the subject JWT: self-mint fallback or brokered re-issue. Direct pass-through and successful Vault-generated plugin identity tokens are unchanged.
- Custom claims are additive only. They do not replace or modify standard JWT claims or trusted Vault-derived claims.
- Configured values are string templates. Pure string literals are valid and do not require interpolation.
- Reserved JWT claims cannot be configured: `iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `jti`.
- Claims in the `vault_` namespace are reserved for trusted Vault-derived identity context and cannot be configured.
- Template rendering fails closed on bad syntax, missing values, collisions, or unsupported non-scalar interpolation.

Trusted template inputs:

- `vault.entity.id`
- `vault.entity.name`
- `vault.entity.namespace_id`
- `vault.entity.metadata.*`
- `vault.alias.name`
- `vault.alias.mount_accessor`
- `vault.alias.mount_type`
- `vault.alias.metadata.*`
- `vault.alias.custom_metadata.*`
- `vault.request.display_name`
- `vault.request.mount_accessor`
- `vault.request.mount_type`
- `vault.request.client_token_accessor`
- `vault.groups`
- `brokered.claims.*`: verified external claims, available only during brokered re-issue

Supported template style:

- direct lookup: `{{ vault.entity.id }}`
- nested lookup: `{{ vault.alias.metadata.arn }}`
- literal + interpolation: `aws/{{ vault.alias.metadata.arn }}`
- list condensation: `{{ join(vault.groups, ",") }}`
- brokered role lookup: `{{ brokered.claims.department }}`

Example role configuration:

```bash
vault write oci/role/developer \
    description="Development environment access" \
    default_ttl=3600 \
    max_ttl=14400 \
    self_mint_custom_claims='{
      "oci_role": "developer",
      "entity_ref": "{{ vault.entity.id }}",
      "aws_arn": "{{ vault.alias.metadata.arn }}",
      "principal": "aws/{{ vault.alias.metadata.arn }}",
      "group_list": "{{ join(vault.groups, \",\") }}"
    }'
```

Example self-mint exchange using that role:

```bash
vault write oci/exchange/developer \
    requested_token_type="urn:oci:token-type:oci-upst"
```

Typical mapping scenarios:

- Add an `oci_role` claim so OCI trust rules can distinguish multiple workload classes minted by the same plugin.
- Copy a trusted alias metadata value such as an AWS ARN into a compact OCI-facing claim.
- Condense group membership into a single string claim using `join(vault.groups, ",")`.
- Build a normalized principal string from trusted Vault context rather than caller-supplied input.

## Template Validation and Limits

Role and brokered mapping writes validate every expression without needing caller data. For example, `{{ vault.entity.id }} {{ forbidden.expression }}` is rejected even though no entity exists during configuration. Stored templates are also fully parsed before rendering. Missing values and incompatible types still fail at exchange time.

Templates are limited to **16 KiB each** and rendered claims to **64 KiB each**, measured in bytes. The output limit includes literals, interpolated values and `join` separators. These are not aggregate JWT limits. Paths use nonempty dot-separated segments without whitespace, control characters, braces, brackets, parentheses, quotes, commas or backslashes; dots in metadata keys cannot be escaped. There is no bracket indexing. Role templates support `join(path, separator)` with exactly two arguments; brokered mapping templates support only `claims.*` scalar lookups. See the [grammar details](../DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md#template-grammar-and-limits).

Existing malformed or oversized stored templates must be repaired before exchange. A valid template write cannot guarantee that every future caller has the referenced data.

## Using Returned Credentials with OCI Clients

Configure the returned OCI token and exchange private key together in a client that supports that credential type. UPST and RPST client setup differs; the plugin does not configure OCI CLI profiles or implement a client credential provider. Live OCI API use is part of the outstanding acceptance tests.

### Session Tokens and Request Signing

UPST and RPST are OCI-signed session tokens containing the OCI principal's identity context and the exchange client's public key. To call OCI APIs, the client needs both the session token and the matching private key:

1. Sign the API request with the private key.
2. Include the session token in the `keyId` parameter of the `Authorization: Signature ...` header, using `keyId="ST$<session-token>"`.
3. OCI validates the session token, resolves the principal, and verifies the request signature with the public key carried in the token. OCI IAM policies determine whether the operation is allowed.

The token alone is insufficient for this signed-request authentication. A `token_type` value of `Bearer` in the exchange response does not change how session tokens authenticate OCI API requests. This exchange keypair is separate from the issuer signing key used to sign subject JWTs.

Oracle documents the public-key binding in its [UPST exchange](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm) and [RPST exchange](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange_grant_type_workload_id-federation.htm) guides. See also [OCI request signatures](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm) and the SDK's [security-token signer](https://docs.oracle.com/en-us/iaas/tools/ruby/latest/OCI/Auth/Signers/SecurityTokenSigner.html) for the token-and-private-key signing contract.

### Capture and Use the Response

To capture a response without displaying credentials, send an owner-only request file through stdin and protect the output from creation:

```bash
umask 077
CREDENTIAL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oci-credentials.XXXXXX")"
vault write -format=json oci/exchange/developer - \
    < /private/path/exchange-request.json > "$CREDENTIAL_DIR/response.json"
```

Use the response with an appropriately configured OCI client and remove the private directory after use. Do not enable shell tracing or copy the response into logs. If the request supplied `public_key`, retain the corresponding caller-owned private key; the response contains no generated key material.

## Troubleshooting Exchange Failures

Exchange errors return fixed classifications and safe correlation metadata rather than raw OCI response bodies or token claims. Use the [security logging guide](security-logging.md) to correlate failures and configure audit records. If decoded resolved-token claims are needed in a controlled test, explicitly enable the [15-minute diagnostic window](security-logging.md#temporary-claim-diagnostics) and protect the response capture.

## Exchange a JWT for OCI RPST

Use RPST when you need resource-principal style token exchange behavior supported by OCI Identity Domains.

```bash
vault write oci/exchange/developer \
    subject_token="eyJhbGciOiJSUzI1NiIs..." \
    requested_token_type="urn:oci:token-type:oci-rpst" \
    res_type="resource_principal"
```

For RPST requests, `res_type` is required and the response will include `rpst_token`. The plugin also sends `rpst_exp` to OCI based on the effective TTL after applying request, role, backend, and Vault mount/system limits.

## API Reference

### Config Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/config` | Read federated identity configuration |
| `POST/PUT` | `/oci/config` | Create or update configuration |
| `DELETE` | `/oci/config` | Delete configuration |

### Exchange Path

| Method | Path | Description |
|--------|------|-------------|
| `POST/PUT` | `/oci/exchange` | Exchange JWT subject token for OCI credentials; when `brokered_subject_token_enabled=true`, a caller-supplied `subject_token` is validated and re-issued before OCI exchange |
| `POST/PUT` | `/oci/exchange/:role` | Exchange JWT subject token for OCI credentials using an explicit plugin role selected from the path; in brokered mode the role contributes existing TTL policy and additive templated `self_mint_custom_claims` only |

#### Request Parameters

| Parameter | Definition |
|---|---|
| <a id="request-subject-token"></a>`subject_token` | External JWT to exchange. Direct mode forwards it unchanged; brokered mode verifies and reissues it. Omit it only when plugin-issued mode is enabled and a token source is available. An explicitly supplied empty token is rejected. |
| <a id="request-requested-token-type"></a>`requested_token_type` | OCI token type: `urn:oci:token-type:oci-upst` (default) or `urn:oci:token-type:oci-rpst`. |
| <a id="request-res-type"></a>`res_type` | OCI resource type for an RPST exchange. Required by this engine when requesting `urn:oci:token-type:oci-rpst`; its value must match the OCI trust configuration. |
| <a id="request-public-key"></a>`public_key` | Optional PEM-encoded SubjectPublicKeyInfo public key (`BEGIN PUBLIC KEY`) to bind into the session token. Keep its matching private key for signing OCI API requests. If omitted, the engine generates an RSA keypair and returns the private key. See [request signing](#session-tokens-and-request-signing). |
| <a id="request-subject-token-audience"></a>`subject_token_audience` | Optional audience override, only when `subject_token` is omitted. It must be allowed by `subject_token_allowed_audiences`. Omission or an empty string keeps the configured default; whitespace-only values are rejected. |
| <a id="request-ttl"></a>`ttl` | Optional positive whole-second duration, as seconds or a supported duration string. Omission or zero selects the role/backend default. Backend, role, and Vault limits cap the result. It bounds the Vault lease and RPST requested lifetime; it does not set UPST expiry. See [TTL policy](configuration.md#roles). |

Unknown request fields are rejected. Select a role through `/oci/exchange/:role`; `role` is not a body parameter.

**Request Body:**
```json
{
  "subject_token": "eyJhbGciOiJSUzI1NiIs...",
  "requested_token_type": "urn:oci:token-type:oci-upst",
  "res_type": "resource_principal",
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "ttl": 3600
}
```
*(Note: `subject_token` is optional when `enable_plugin_issued_subject_token=true` and the plugin-issued subject-token mode can resolve a token. `subject_token_audience` is only used for plugin-issued subject tokens. When `brokered_subject_token_enabled=true` and the caller supplies `subject_token`, the plugin validates and re-issues that token before OCI exchange. The plugin always sends `subject_token_type=jwt` to OCI. Select an explicit role through `/oci/exchange/:role`, not a request body field.)*

`requested_token_type` defaults to `urn:oci:token-type:oci-upst`. Supported values:

- `urn:oci:token-type:oci-upst`
- `urn:oci:token-type:oci-rpst` (requires `res_type`)

Credential expiry and Vault leases:

- `credential_expiry_known=true` means the OCI response supplied a positive integer `expires_in`. The plugin derives a conservative deadline from the time the HTTP request was dispatched plus that lifetime, so network and processing time cannot extend it. `expires_at` is that UTC deadline; `expires_in` is the remaining lifetime rounded down to whole seconds when the response is built. These fields describe OCI credential lifetime, not Vault policy.
- Vault lease TTL and its maximum are capped at both local policy and known remaining credential lifetime. For example, OCI returning 10 seconds under a one-hour policy produces a lease of at most 10 seconds (usually slightly less after elapsed time). Conversely, an OCI credential with one hour remaining can have a ten-minute Vault lease; its reported expiry still reflects OCI's lifetime.
- If OCI omits `expires_in` or returns `null`, `credential_expiry_known=false` and both expiry fields are omitted. The Vault lease retains its policy duration, which is **not evidence of OCI expiry**. The plugin does not infer expiry from unverified JWT claims or requested RPST TTL. Clients must handle unknown expiry and credential rejection explicitly.
- An explicit zero, negative, fractional, non-integer, or overflowing OCI `expires_in` is rejected. A known credential with less than one whole second remaining is also rejected; no credential/key response or lease is returned. Remaining lifetime is measured at response construction, not client receipt.
- These leases are nonrenewable. Revocation completes Vault-side lease handling but makes no OCI invalidation request. Removing the Vault lease does not establish that the OCI credential has stopped working. Support for upstream revocation must be assessed per credential type before implementation.

Compatibility: clients must no longer assume `expires_in`/`expires_at` are always present or equal to `lease_duration`. This response correction applies to both UPST and RPST. OCI expiry is an upper-bound lifetime estimate, not a guarantee that a credential will remain authorized until that time.

<a id="oci-rpst-exp"></a>
TTL note:

- For RPST, the plugin uses backend, role, and Vault mount/system ceilings to bound the `rpst_exp` value sent to OCI.
- For UPST, OCI determines the token lifetime; plugin TTL settings affect Vault lease metadata, not OCI-side UPST expiration.

### JWKS Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/jwks` | Return JWKS for self-mint signing key (used for OCI trust setup) |

Example:

```bash
vault read oci/jwks
```

### Roles Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/role/:name` | Read a role |
| `POST/PUT` | `/oci/role/:name` | Create or update a role |
| `DELETE` | `/oci/role/:name` | Delete a role |
| `LIST` | `/oci/role` | List all roles |

Role fields:

- `description`
- `default_ttl`
- `max_ttl`
- <a id="role-self-mint-custom-claims"></a>`self_mint_custom_claims`: JSON object of output claim name to string template for additive self-minted claims; supports pure string literals and trusted-context interpolation. See [role-scoped templates](#role-scoped-custom-claims-for-self-mint).
