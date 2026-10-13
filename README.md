# HashiCorp Vault OCI Secrets Engine

A HashiCorp Vault secrets engine plugin that exchanges 3rd party OIDC/OAuth JWT tokens for Oracle Cloud Infrastructure (OCI) session tokens.

## Overview

This plugin enables **federated identity** workflows by allowing users to exchange JWT tokens from external Identity Providers (IdPs) for temporary OCI session tokens. This eliminates the need to store long-lived OCI API keys in Vault.

### Sequence Diagrams (Current Implemented Flows)

These diagrams describe the implemented request flows in the plugin.

Actor definitions used in diagrams:

- **Client/Workload**: The caller (app, CI job, script, or human) that invokes `vault write oci/exchange` or `vault write oci/exchange/<role>`.
- **Vault OCI Credential Engine**: This secrets-engine plugin instance mounted in Vault.
- **Vault Storage**: Plugin storage view used for reading config and role entries.
- **Vault System View**: Vault runtime interface available to plugins; used by the default subject-token callback to call `GenerateIdentityToken` when available.
- **Subject Token Callback**: Plugin hook used when `subject_token` is omitted and `enable_plugin_issued_subject_token=true`. This is the plugin-issued subject-token mode. The default callback tries Vault identity-token generation first, then self-mints only if needed and configured.
- **OCI Token Endpoint**: OCI Identity Domain OAuth token exchange endpoint (`/oauth2/v1/token`).

#### 1) Subject Token Exchange (Caller Provides `subject_token`)

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange/<role>` with `subject_token`
    V->>V: Validate exchange schema; reject unknown fields before processing
    V->>S: Read backend config and optional plugin role
    S-->>V: Config and role constraints
    V->>V: Validate request fields and TTL
    V->>V: If `subject_token_role_mappings` exist, derive Vault role from caller JWT
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    Note over V: Roles with removed filter settings require explicit cleanup
    V->>V: Resolve TTL and cap at backend, role and Vault mount/system maxima
    V->>O: POST `/oauth2/v1/token` with Basic auth, `subject_token_type=jwt`, `requested_token_type`, base64 SPKI `public_key`, optional `res_type`, RPST `rpst_exp`
    O-->>V: OCI UPST or RPST
    V->>V: Report OCI expiry when known; cap nonrenewable lease to remaining lifetime
    V-->>C: Vault secret response with OCI token, lease, and generated private key only when the engine generated the exchange keypair
```

Client sends `subject_token`; when a role-specific route is used, the plugin loads that role's constraints before performing token exchange against OCI.

#### 1.1) Caller JWT Role Mapping Variant

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange` with caller JWT
    V->>V: Validate exchange schema; reject unknown fields before processing
    V->>S: Read backend config and role policy
    S-->>V: `subject_token_role_mappings`, role entries
    V->>V: Parse caller JWT payload only
    V->>V: Evaluate ordered role-mapping rules
    V->>V: First matching rule selects Vault role
    V->>S: Read derived Vault role entry
    S-->>V: Role TTL and local policy constraints

    alt Mapping rule matches
        Note over V: Roles with removed filter settings require explicit cleanup
        V->>V: Resolve TTL and cap at backend, role and Vault mount/system maxima
        V->>O: POST `/oauth2/v1/token`
        O-->>V: OCI session token
        V->>V: Report OCI expiry when known; cap nonrenewable lease to remaining lifetime
        V-->>C: Success response
    else No rule matches
        V-->>C: Error response before OCI call
    end
```

This is a caller-supplied `subject_token` variant of flow 1. When `subject_token_role_mappings` are configured, the engine derives the effective Vault role from trusted JWT claims before OCI exchange instead of relying on an explicit role path.

#### 1.2) Brokered Caller JWT Variant

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant SV as Vault System View
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange[/<role>]` with external `subject_token`
    V->>V: Validate exchange schema; reject unknown fields before processing
    V->>S: Read backend config and optional explicit role
    S-->>V: Brokered trust config, mappings, self-mint key, optional role
    V->>V: Check `brokered_subject_token_enabled=true`
    V->>V: Validate JWT signature, `iss`, `aud`, `exp`, `nbf`, `iat`
    V->>V: Render mapped claims from validated external claims
    V->>SV: Read trusted Vault request and identity context
    SV-->>V: Entity, linked aliases, groups
    Note over V: Emit alias claims only for configured auth accessor; fail on missing or ambiguous match
    V->>V: Build brokered self-minted JWT
    V->>V: Render role `self_mint_custom_claims` templates only when `/exchange/<role>` is used
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    Note over V: Roles with removed filter settings require explicit cleanup
    V->>V: Resolve TTL and cap at backend, role and Vault mount/system maxima
    V->>O: POST `/oauth2/v1/token` with plugin-issued brokered `subject_token`
    O-->>V: OCI UPST or RPST
    V->>V: Report OCI expiry when known; cap nonrenewable lease to remaining lifetime
    V-->>C: Vault secret response with OCI token and generated exchange private key only when the engine generated the exchange keypair
```

This flow is intentionally separate from direct pass-through. When `brokered_subject_token_enabled=true` and the caller supplies `subject_token`, the plugin validates the external JWT locally, maps claims into a normalized claim set, self-mints a plugin-issued JWT, and exchanges that re-issued token with OCI.

#### 2) Exchange Without `subject_token` (Plugin-Issued Subject Token Mode)

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant SV as Vault System View
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange[/<role>]` without `subject_token`
    V->>V: Validate exchange schema; reject unknown fields before processing
    V->>S: Read backend config and optional plugin role
    S-->>V: Config and role constraints
    V->>V: Check `enable_plugin_issued_subject_token=true`
    V->>V: Resolve default audience or normalize and validate `subject_token_audience` against allowlist
    V->>SV: `GenerateIdentityToken(audience)`
    SV-->>V: Vault-issued identity token
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    Note over V: Roles with removed filter settings require explicit cleanup
    V->>V: Resolve TTL and cap at backend, role and Vault mount/system maxima
    V->>O: POST `/oauth2/v1/token` with Basic auth, `subject_token_type=jwt`, `requested_token_type`, base64 SPKI `public_key`, optional `res_type`, RPST `rpst_exp`
    O-->>V: OCI UPST or RPST
    V->>V: Report OCI expiry when known; cap nonrenewable lease to remaining lifetime
    V-->>C: Vault secret response with OCI token, lease, and generated private key only when the engine generated the exchange keypair
```

Client omits `subject_token`; plugin uses its plugin-issued subject-token mode when enabled. Default callback behavior is: `GenerateIdentityToken` first, then self-mint JWT only if needed and configured.

#### 2.1) Plugin-Issued Self-Mint Variant

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant SV as Vault System View
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange[/<role>]` without `subject_token`
    V->>V: Validate exchange schema; reject unknown fields before processing
    V->>S: Read backend config and self-mint key
    S-->>V: Config, role constraints, signing key
    V->>V: Check plugin-issued mode is enabled
    V->>V: Resolve default audience or normalize and validate `subject_token_audience` against allowlist
    V->>SV: `GenerateIdentityToken(audience)`
    SV-->>V: Identity token unavailable
    V->>SV: Read trusted Vault request and identity context
    SV-->>V: Entity, linked aliases, groups
    Note over V: Emit alias claims only for configured auth accessor; fail on missing or ambiguous match
    V->>V: Build JWT with Vault-derived claims
    V->>V: Sign self-minted JWT with plugin signing key
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    Note over V: Roles with removed filter settings require explicit cleanup
    V->>V: Resolve TTL and cap at backend, role and Vault mount/system maxima
    V->>O: POST `/oauth2/v1/token` with Basic auth, self-minted `subject_token`, `subject_token_type=jwt`, `requested_token_type`, base64 SPKI `public_key`, optional `res_type`, RPST `rpst_exp`
    O-->>V: OCI UPST or RPST
    V->>V: Report OCI expiry when known; cap nonrenewable lease to remaining lifetime
    V-->>C: Vault secret response with OCI token, lease, and generated private key only when the engine generated the exchange keypair
```

Client omits `subject_token`; Vault identity-token generation is unavailable, so the plugin self-mints the subject token from trusted Vault context and then exchanges it with OCI.

### Terminology
When referring to token exchanges in this plugin, we use standard OAuth 2.0 (RFC 8693) and OCI Identity nomenclature:

- **Subject Token**: The initial JWT (JSON Web Token) provided by an external Identity Provider (e.g., Auth0, Azure AD, Okta, Vault Enterprise WIF). This is the token that proves the user's or workload's identity.
- **Token Exchange**: The process of trading the *Subject Token* for an OCI-specific token. The plugin acts as the intermediary, securely presenting the Subject Token to OCI over the `urn:ietf:params:oauth:grant-type:token-exchange` grant type.
- **UPST (User Principal Session Token)**: The resulting session token issued by Oracle Cloud Infrastructure. Once the exchange succeeds, OCI returns a UPST. This token is what the end-user or workload actually uses to authenticate API calls against OCI services.

## Features

- **JWT Token Exchange**: Exchange OIDC/OAuth tokens for OCI session tokens
- **UPST and RPST Support**: Request either `urn:oci:token-type:oci-upst` or `urn:oci:token-type:oci-rpst`
- **Returned OCI Key Material**: When the engine generates the exchange RSA key pair, responses include the generated PEM-encoded `private_key` for request-signing workflows
- **Plugin-Issued Subject Token Mode**: If `subject_token` is omitted and `enable_plugin_issued_subject_token=true`, the plugin resolves a token itself (default callback: Vault identity token first if availble in the version of vualt, self-mint if configured)
- **Brokered Subject Token Mode**: If `subject_token` is supplied and `brokered_subject_token_enabled=true`, the plugin validates the external JWT, maps claims, self-mints a plugin-issued JWT, and exchanges the re-issued token with OCI
- **Role-based TTL Policies**: Define roles with default and maximum TTL constraints
- **Lease Management**: OCI tokens are issued as Vault secrets with TTL-based lease handling


## Prerequisites

- Go 1.21 or later
- HashiCorp Vault 1.12+ (dev mode or server mode)
- OCI tenancy with Identity Domain configured
- External Identity Provider (IdP) integrated with OCI IAM

## Installation

### Build the Plugin

For contributor-oriented build, local Vault dev, and test workflows, use [CONTRIBUTING.md](CONTRIBUTING.md#building-and-local-development) as the source of truth.

```bash
# Clone the repository
git clone https://github.com/gordon/Hashicorp-OCI-credential-engine.git
cd Hashicorp-OCI-credential-engine

# Build the plugin
make build
```

### Register the Plugin with Vault

For local development, prefer `./scripts/dev_vault.sh start`. That helper rebuilds the plugin, starts a checkout-managed loopback Vault with private runtime files and a random root token, registers the plugin, enables the `oci` mount, and can seed `oci/config` from an owner-only `.env.local` file in the repo root. It requires Python 3.9+ and refuses an unrelated Vault target. The smoke helper checks claims without printing credentials and cleans up its test resources. See the [upgrade notes](CONTRIBUTING.md#dev-helper-security-and-upgrade-notes) before using these helpers with an older dev setup.

For the detailed local-development and test workflow, including `dev_vault.sh`, `register_plugin.sh`, `make test-unit`, and `make test-integration`, see [CONTRIBUTING.md](CONTRIBUTING.md#testing-locally-with-vault).

The manual steps below are for non-dev setups or operators who want to register the plugin explicitly.

The helper script cannot set environment variables in your current shell by itself. To load the dev Vault CLI environment after startup, run:

```bash
eval "$(./scripts/dev_vault.sh env)"
```

Dev Note: If you want dev startup to reapply backend config automatically, create `.env.local` in the repo root with at least:

```bash
OCI_DOMAIN_URL="https://idcs-xxxxx.identity.oraclecloud.com:443"
OCI_CLIENT_ID="..."
OCI_CLIENT_SECRET="..."
```

Optional `.env.local` settings also map directly to `oci/config`, including:
- `OCI_DEFAULT_TTL`
- `OCI_MAX_TTL`
- `OCI_ENABLE_PLUGIN_ISSUED_SUBJECT_TOKEN`
- `OCI_STRICT_ROLE_NAME_MATCH`
- `OCI_SUBJECT_TOKEN_ROLE_MAPPINGS`
- `OCI_SUBJECT_TOKEN_ALLOWED_AUDIENCES`
- `OCI_SUBJECT_TOKEN_IDENTITY_ALIAS_MOUNT_ACCESSOR`
- `OCI_SUBJECT_TOKEN_SELF_MINT_ENABLED`
- `OCI_SUBJECT_TOKEN_SELF_MINT_ISSUER`
- `OCI_SUBJECT_TOKEN_SELF_MINT_AUDIENCE`
- `OCI_SUBJECT_TOKEN_SELF_MINT_TTL_SECONDS`
- `OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY`
- `OCI_DEBUG_RETURN_RESOLVED_SUBJECT_TOKEN_CLAIMS`
- `OCI_BROKERED_SUBJECT_TOKEN_ENABLED`
- `OCI_BROKERED_SUBJECT_TOKEN_TRUST_TYPE`
- `OCI_BROKERED_SUBJECT_TOKEN_ISSUER`
- `OCI_BROKERED_SUBJECT_TOKEN_ALLOWED_AUDIENCES`
- `OCI_BROKERED_SUBJECT_TOKEN_ALLOWED_ALGS`
- `OCI_BROKERED_SUBJECT_TOKEN_CLOCK_SKEW_SECONDS`
- `OCI_BROKERED_SUBJECT_TOKEN_JWKS_URL`
- `OCI_BROKERED_SUBJECT_TOKEN_JWKS_JSON`
- `OCI_BROKERED_SUBJECT_TOKEN_PUBLIC_KEYS`
- `OCI_BROKERED_SUBJECT_TOKEN_CLAIM_MAPPINGS`

Dev Note: If JWT self-mint is enabled in `.env.local` and `OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY` is not set, `./scripts/dev_vault.sh start` will create and reuse a local ignored PEM file at `.vault-dev-self-mint-key.pem`. That keeps the self-mint JWKS stable across dev restarts.

1. Calculate the SHA256 checksum of the plugin binary:
```bash
sha256sum bin/vault-plugin-secrets-oci
```

2. Register the plugin in Vault's catalog:
```bash
# If using a local dev server, ensure VAULT_ADDR is set to http
export VAULT_ADDR='http://127.0.0.1:8200'

vault write sys/plugins/catalog/secret/oci \
    sha_256="<SHA256_CHECKSUM>" \
    command="vault-plugin-secrets-oci"
```

3. Enable the secrets engine:
```bash
vault secrets enable -path=oci -plugin-name=oci plugin
```

### Self-Mint JWKS Publication Workflow

If you enable built-in self-minting, the plugin can expose the signing public key as JWKS at `oci/jwks`. That Vault path is intended as an operator export point, not as the final OCI discovery URL.

Recommended workflow:

1. Configure self-mint on the plugin.
2. Read the JWKS from Vault:

```bash
vault read -format=json oci/jwks
```

3. Publish that JWKS document to an HTTPS location OCI Identity Domains can reach, for example:
   - GitHub Pages
   - OCI Object Storage static website hosting
   - another normal HTTPS-hosted file
4. Configure OCI token exchange trust to use that published JWKS URL.
5. If the self-mint signing key changes, publish the updated JWKS before relying on newly minted tokens.

Security Note: It is important to strictly control who is allowed to update the JWKS since that is part of the trust boundary 

## Configuration

### OCI Federated Identity Setup

Before using the plugin, configure it with your OCI Identity Domain details:

```bash
vault write oci/config \
    domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..xxxxx" \
    client_secret="<oauth-client-secret>" \
    default_ttl=3600 \
    max_ttl=28800 \
    subject_token_role_mappings='[{"claim":"vault_role","op":"eq","value":"developer","role":"developer"}]' \
    enable_plugin_issued_subject_token=true \
    strict_role_name_match=false \
    subject_token_self_mint_enabled=false \
    subject_token_allowed_audiences="urn:oci:test,urn:oci:prod" \
    brokered_subject_token_enabled=true \
    brokered_subject_token_trust_type="public_keys" \
    brokered_subject_token_issuer="https://issuer.example.com" \
    brokered_subject_token_allowed_audiences="urn:test" \
    brokered_subject_token_allowed_algs="RS256" \
    brokered_subject_token_public_keys='["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"]' \
    brokered_subject_token_claim_mappings='{"external_sub":"{{ claims.sub }}","principal":"svc/{{ claims.org }}/{{ claims.user.id }}"}'
```

**Parameters:**
- `domain_url`: OCI Identity Domain URL (for example: `https://idcs-xxxxx.identity.oraclecloud.com`)
- `client_id`: OAuth Confidential Application client ID in the OCI Identity Domain
- `client_secret`: OAuth Confidential Application client secret in the OCI Identity Domain
- `default_ttl`: Default Vault lease TTL for exchanged credentials, and the default `rpst_exp` requested from OCI for RPST exchanges when a request TTL is not supplied (default: 3600)
- `max_ttl`: Maximum Vault lease TTL for exchanged credentials, and the maximum `rpst_exp` value allowed for RPST exchanges (default: 86400)
- `subject_token_role_mappings`: Optional JSON array of ordered rules used to derive a Vault role from a caller-supplied `subject_token`
  Each rule has:
  `claim`: JWT claim name to inspect
  `op`: match operator, one of `eq`, `co`, `sw`
  `value`: string to compare against the claim value
  `role`: Vault role name to apply when the rule matches
- `enable_plugin_issued_subject_token`: When true, plugin-issued subject-token mode is enabled when the caller omits `subject_token` (default: `true`)
- `strict_role_name_match`: When true, requires role names to match `[A-Za-z0-9._:-]+` (default: `false`)
- `subject_token_self_mint_enabled`: Enables built-in self-mint in plugin-issued subject-token mode when Vault identity-token generation is unavailable (default: `false`)
- `subject_token_self_mint_issuer`: Required when self-mint is enabled
- `subject_token_self_mint_audience`: Audience for self-minted token (default: `urn:mace:oci:idcs`)
- `subject_token_allowed_audiences`: Optional allowlist for request-level audience override in plugin-issued subject-token mode via `subject_token_audience`. Entries are trimmed and deduplicated; blank entries, values over 512 bytes, and control characters remaining after trimming are rejected on configuration writes, including partial updates. An empty list disables overrides.
- `subject_token_self_mint_ttl_seconds`: TTL for self-minted token in seconds (default: `600`)
- `subject_token_self_mint_private_key`: Optional PEM RSA private key. If omitted while self-mint is enabled, the plugin generates one and stores it in Vault plugin storage
- `debug_return_resolved_subject_token_claims`: Development-only flag that includes decoded claims from the resolved subject token in `oci/exchange` responses, including error responses
- `brokered_subject_token_enabled`: Enables explicit brokered mode for caller-supplied `subject_token` values (default: `false`)
- `brokered_subject_token_trust_type`: Required when brokered mode is enabled. Supported values: `oidc_discovery`, `jwks_url`, `jwks_json`, `public_keys`
- `brokered_subject_token_issuer`: Required when brokered mode is enabled. This is the expected incoming `iss` claim and the OIDC discovery issuer when `brokered_subject_token_trust_type=oidc_discovery`
- `brokered_subject_token_allowed_audiences`: Required non-empty audience allowlist for incoming brokered-token validation
- `brokered_subject_token_allowed_algs`: Required non-empty signing algorithm allowlist for incoming brokered-token validation. Supported values are RSA (`RS256`, `RS384`, `RS512`) and EC (`ES256`, `ES384`, `ES512`)
- `brokered_subject_token_clock_skew_seconds`: Optional clock-skew tolerance for brokered `exp`, `nbf`, and `iat` validation (default: `0`)
- `brokered_subject_token_jwks_url`: Required when `brokered_subject_token_trust_type=jwks_url`; must use HTTPS unless loopback-only debug HTTP is explicitly enabled
- `debug_allow_brokered_http`: Defaults to `false`. Allows HTTP trust retrieval only from `localhost` or loopback IP literals for local testing; it does not disable HTTPS certificate verification
- `brokered_subject_token_allowed_jwks_origins`: Additional exact origins (`https://host[:port]`, no path) allowed for discovered JWKS URLs hosted separately from the issuer. The issuer origin is allowed automatically
- `brokered_subject_token_jwks_json`: Required when `brokered_subject_token_trust_type=jwks_json`
- `brokered_subject_token_public_keys`: Required when `brokered_subject_token_trust_type=public_keys`; accepts one PEM public key or a JSON array of PEM public keys
- `brokered_subject_token_claim_mappings`: Optional JSON object of output-claim to string template. Templates may reference validated incoming claims such as `{{ claims.sub }}` or `svc/{{ claims.org }}/{{ claims.user.id }}`

`oci/config` supports incremental updates. After the initial configuration is created, later `vault write oci/config ...` calls may update only the fields you want to change.

If `subject_token_self_mint_enabled=true`, OCI must be able to discover the published JWKS for the self-mint signing key. See [Self-Mint JWKS Publication Workflow](#self-mint-jwks-publication-workflow).

Brokered mode also relies on the existing self-mint signing configuration because the plugin re-issues a new JWT before calling OCI. Explicit `/oci/exchange/:role` requests are still allowed in brokered mode, but role contribution is limited to the existing TTL controls and additive templated `self_mint_custom_claims`. Existing `subject_token_role_mappings` remain part of the direct pass-through flow and are not reused in brokered mode.

### Brokered remote trust and key rotation

Remote discovery and JWKS retrieval require HTTPS by default. Discovery must return an `issuer` exactly equal to the configured issuer, including its path/trailing slash. A discovered JWKS URL must use the issuer origin or an explicitly configured `brokered_subject_token_allowed_jwks_origins` entry. Redirects are rejected, including redirects from the OCI token endpoint.

Trust retrieval uses direct connections rather than environment proxies. Resolved private, loopback, link-local, multicast, and unspecified addresses are rejected; the debug exception permits only loopback connections to `localhost` or loopback IP literals. DNS addresses are checked before dialing, and the checked IP is dialed directly. For private-network IdPs, use managed inline `jwks_json` or `public_keys`; this version does not provide a private-network remote-fetch override.

Discovery/JWKS documents and incoming brokered JWTs are limited to 1 MiB. Key sets are limited to 64 keys. Verification uses suitable public signing keys only: RSA at least 2048 bits or the EC curve required by the selected algorithm. JWK `use`, `alg`, and `key_ops` metadata constrain key use. A JWT `kid` must select a matching JWKS key; explicit PEM `public_keys` have no key IDs and are tried against the signature independently of `kid`.

Each mount caches one remote key set for five minutes. Concurrent misses share a refresh. An unknown `kid` can trigger a refresh after a 30-second cooldown; repeated failures also have a 30-second cooldown. Failed refreshes invalidate cached keys and fail closed rather than serving stale material. Changes to remote trust URLs, issuer, allowed origins, or debug policy cannot reuse the previous policy's cache entry.

For upstream key rotation, publish old and new verification keys together using distinct key IDs before signing with the new key. Allow at least five minutes for caches to pick up the publication before switching signers. Retain the old key until old tokens and the cache window have expired. Removing a compromised key from remote JWKS is not instantaneous revocation: a cached key may remain accepted for up to five minutes. This upstream verification cache does not implement rotation of the plugin's own self-mint signing key.

For a local JWKS test server, an existing backend can be updated with:

```bash
vault write oci/config \
    debug_allow_brokered_http=true \
    brokered_subject_token_trust_type=jwks_url \
    brokered_subject_token_jwks_url="http://127.0.0.1:8080/jwks.json"
```

To return to production, set the remote URL to HTTPS and `debug_allow_brokered_http=false` in the same update. Existing HTTP configurations require this migration; they are no longer silently accepted. Remote key servers must return a direct HTTP 200 JSON response.

The plugin keeps the private signing key in Vault plugin storage. The published JWKS contains only the public key material.

For local debugging of plugin-issued subject tokens, you can temporarily enable:

```bash
vault write oci/config \
    debug_return_resolved_subject_token_claims=true
```

Then `vault write -force -format=json oci/exchange` will include `data.resolved_subject_token_claims` even when OCI rejects the exchange. This flag is intended only for development and troubleshooting.

### Multiple OCI Accounts or Identity Domains

This backend is designed around one OCI trust/config boundary per mount. A single mount has one `oci/config` entry, so it represents one OCI Identity Domain and one confidential application configuration at a time.

If you need to work with multiple OCI accounts, identity domains, or separate trust boundaries, mount the plugin multiple times at different paths. For example:

```bash
vault secrets enable -path=oci-dev -plugin-name=oci plugin
vault secrets enable -path=oci-prod -plugin-name=oci plugin
```

Then configure each mount separately with its own `oci/config` and roles.

### Roles

Create roles to define Vault lease policy and RPST TTL constraints. OCI UPST exchange does not currently let the client request token lifetime through the token-exchange call, so these TTL settings only directly shape the OCI request for RPST via `rpst_exp`. For UPST, they mainly affect Vault-side lease metadata today.

TTL selection uses an explicit positive request `ttl`, otherwise the role default, otherwise the backend default. An omitted or zero request `ttl` selects the default. The result is capped at the lowest positive backend maximum, role maximum, and effective Vault mount/system maximum returned by `SystemView.MaxLeaseTTL()`. A role can tighten the backend ceiling but cannot raise it. This applies to explicit and JWT-mapped roles and to every exchange mode. The capped policy duration is sent as RPST `rpst_exp`. After exchange, Vault lease duration is additionally capped to known remaining OCI credential lifetime; OCI determines the lifetime actually granted.

Backend and role `default_ttl`/`max_ttl` writes require positive whole-second durations with `default_ttl <= max_ttl`. Supported duration strings such as `1h` remain accepted. Zero, negative, fractional-second, and overflowing policy values are rejected. Each value is bounded to 9,223,372,036 seconds before nanosecond conversion. Request `ttl` uses the same range, with zero additionally allowed to select the default. A fractional Vault ceiling is rounded down to whole seconds; a positive ceiling below one second fails closed.

Examples of TTL validation and selection:

| Input or policy | Result |
|---|---|
| `default_ttl=60 max_ttl=600` | Valid policy |
| `default_ttl=3600 max_ttl=600` | Rejected: the policy's default exceeds its own maximum |
| Configured `default_ttl=0`, `max_ttl=-60`, or `default_ttl="500ms"` | Rejected; the stored configuration is unchanged |
| Request `ttl=0`, or no `ttl` | Select the role/backend default, then apply all ceilings |
| Role default/max of 3600 seconds; backend default/max of 600 seconds | Valid policies; exchange TTL is capped at 600 seconds |
| The same policies with a Vault maximum of 300 seconds | Exchange TTL is capped at 300 seconds |

On upgrade, repair invalid stored backend/role policies before exchanging tokens. Partial backend updates revalidate the complete TTL pair; lowering `max_ttl` below the current default requires lowering `default_ttl` in the same write. A role default may exceed the backend or Vault maximum and is capped at exchange time, so lowering backend policy also constrains existing roles. Legacy zero role values inherit backend settings, but new role writes must use positive values. The `subject_token_self_mint_ttl_seconds` setting controls a different token and is not changed by these exchanged-credential TTL rules.

```bash
# Create a development role
vault write oci/role/developer \
    description="Development environment access" \
    default_ttl=3600 \
    max_ttl=14400

# Create a production role with shorter TTL limits
vault write oci/role/prod \
    description="Production environment access" \
    default_ttl=1800 \
    max_ttl=3600
```

**Role Parameters:**
- `default_ttl`: Default Vault lease TTL for credentials issued under the role. Also used as the default `rpst_exp` requested from OCI for RPST exchanges when a request TTL is not supplied.
- `max_ttl`: Maximum Vault lease TTL for credentials issued under the role. Also used as the maximum `rpst_exp` value allowed for RPST exchanges.

### Removed role filter fields and upgrade cleanup

`allowed_subjects` and `allowed_groups` have been removed. They were stored metadata and never enforced authorization. They are no longer accepted role parameters, stored in new role records, or returned as role fields. Role writes now reject all unknown fields, including these two names even when their values are empty or null.

Existing stored roles with nonempty values (or malformed legacy values) require explicit cleanup. Reads return the supported fields plus a warning naming the removed fields; listing and deletion remain available. Exchange through an affected named or JWT-mapped role fails, and ordinary writes cannot silently overwrite it. Missing, empty-array, or null legacy values do not block role use.

Before upgrading, identify affected roles and review the actual Vault ACLs and OCI trust/authorization policies. To clean up an affected role:

1. Read and retain its supported configuration: description, default/max TTLs, and `self_mint_custom_claims`. Review the warning; the removed filters never supplied access protection.
2. Confirm the intended caller permissions are implemented through Vault and OCI controls. Direct `subject_token_role_mappings` remains supported and intentionally delegates role selection.
3. Explicitly delete the affected role with `vault delete oci/role/<name>`.
4. Recreate it with the retained supported parameters, omitting both removed fields. Role writes apply defaults to omitted values, so supply all settings you intend to retain.
5. Read it back and verify exchange with an authorized caller. The role is unavailable between deletion and recreation; coordinate that window with its consumers.

The plugin does not automatically delete or migrate nonempty removed settings, and no additional cleanup endpoint or bypass flag is provided. Subject/group filtering can be reconsidered only when a concrete use case defines the trusted identity and claims to constrain.

## Usage

### Exchange a JWT for OCI Credentials

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
- Use bare `oci/exchange` when `subject_token_role_mappings` are configured and the engine should derive the effective Vault role from trusted JWT claims.
- If `public_key` is not supplied, the engine generates a fresh RSA key pair for the exchange and returns only the generated `private_key`.

*Reference: Oracle JWT-to-UPST flow and request parameters are documented in [Token Exchange Grant Type: Exchanging a JSON Web Token for a UPST](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm#jwt_token_exchange__get-oci-upst).*

**Response:**
```json
{
  "data": {
    "access_token": "eyJ...",
    "session_token": "Atbv...",
    "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE...",
    "requested_token_type": "urn:oci:token-type:oci-upst",
    "token_type": "Bearer",
    "credential_expiry_known": true,
    "expires_in": 3600,
    "expires_at": "2024-01-15T10:30:00Z"
  },
  "lease_id": "oci/exchange/...",
  "lease_duration": 3600,
  "renewable": true
}
```

If `public_key` is provided in the request, the plugin will not return `private_key` or `public_key` in the response.
This applies to both caller-supplied `subject_token` mode and plugin-issued self-mint mode: if the caller supplies `public_key`, the plugin uses that key in the OCI token exchange payload and does not generate or return exchange key material.

### Caller-Supplied Subject Token Flow (JWT Claim to Vault Role Mapping)

Use this flow when callers supply their own JWTs and the plugin should derive the effective Vault role from trusted JWT claims before applying local Vault constraints.

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

### Brokered Caller-Supplied Subject Token Flow (Template-Based Claim Mapping)

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

2. The upstream JWT can carry whatever external claim shape your issuer provides, for example:

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

See [DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md](DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md) for full architecture and implementation details.

*Important: If the caller omits `subject_token`, the plugin can only continue when `enable_plugin_issued_subject_token=true`. In the default callback flow, the plugin first tries to obtain a Vault-issued identity token. If Vault identity-token generation is unavailable, the plugin falls back to self-mint only when self-mint is explicitly enabled and configured. In that self-mint case, the JWT is built from trusted Vault runtime identity context. The selected exchange role is not copied into the token, although it may still apply local plugin constraints or add configured templated custom claims.*

### Default Self-Mint Claim Set

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

### Explicit Linked Alias Selection

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

### Role-Scoped Custom Claims For Self-Mint

Roles may optionally contribute additional custom claims to self-minted subject tokens through string templates stored in `self_mint_custom_claims`.

Guardrails:
- This applies only to the plugin self-mint path when the request selects an explicit role.
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

Supported template style:
- direct lookup: `{{ vault.entity.id }}`
- nested lookup: `{{ vault.alias.metadata.arn }}`
- literal + interpolation: `aws/{{ vault.alias.metadata.arn }}`
- list condensation: `{{ join(vault.groups, ",") }}`

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

### Using with OCI CLI

```bash
# Get credentials from Vault
CREDS=$(vault write -format=json oci/exchange/developer subject_token="$JWT")

# Extract the session token
export OCI_CLI_AUTH=security_token
export OCI_CLI_SECURITY_TOKEN=$(echo $CREDS | jq -r '.data.session_token')

# Persist key material returned by the plugin
mkdir -p ~/.oci
echo "$CREDS" | jq -r '.data.private_key' > ~/.oci/key.pem
chmod 600 ~/.oci/key.pem

# Use OCI CLI
oci iam user list
```

The returned `private_key` is PEM-encoded and can be used by tools or SDK wrappers that require explicit key material for OCI request signing, which aligns with OCI's UPST public-key workflow. Treat `private_key` as sensitive secret material.

### Exchange a JWT for OCI RPST

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

### JWKS Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/jwks` | Return JWKS for self-mint signing key (used for OCI trust setup) |

Example:

```bash
vault read oci/jwks
```

**Request Body:**
```json
{
  "subject_token": "eyJhbGciOiJSUzI1NiIs...",
  "subject_token_audience": "urn:oci:test",
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

TTL note:
- For RPST, the plugin uses backend, role, and Vault mount/system ceilings to bound the `rpst_exp` value sent to OCI.
- For UPST, OCI determines the token lifetime; plugin TTL settings affect Vault lease metadata, not OCI-side UPST expiration.

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
- `self_mint_custom_claims`: JSON object of output claim name to string template for additive self-minted claims; supports pure string literals and trusted-context interpolation

## Architecture Details

### Token Exchange Flow

1. **User authenticates** with external IdP and receives JWT
2. **User submits JWT** to Vault plugin's `/exchange` endpoint
3. **Plugin calls OCI IAM** token exchange API
4. **OCI validates** the JWT against the federated IdP
5. **OCI returns** the requested token type (UPST or RPST)
6. **Plugin returns** credentials to user with Vault lease

### Security Considerations

- **Threat Model**: For a deep-dive into the trust architecture, attack vectors, and mitigations (especially concerning self-minted and brokered modes), see [THREAT_MODEL.md](THREAT_MODEL.md).
- **Token Validation**: In direct pass-through mode, OCI IAM validates the caller-supplied subject token during exchange. In brokered mode, the plugin validates the external JWT locally, self-mints a new plugin-issued JWT, and OCI validates that brokered JWT during exchange.
- **TTL Semantics**: RPST requests can be bounded by plugin TTL policy. UPST lifetime is determined by OCI; plugin TTL settings mainly control Vault lease metadata for UPST responses.
- **Lease Management**: Vault lease lifecycle is applied to issued secrets, but this plugin does not call OCI to invalidate exchanged credentials on revocation. Leases are nonrenewable; see the expiry contract above.
- **Audit Logging**: All token exchanges are logged to Vault audit log
- **Self-Mint Key Handling**: When `subject_token_self_mint_enabled=true` and no private key is supplied, the plugin generates an RSA key pair and persists the private key in plugin storage. The key is never returned by `read oci/config`.

### Access Controls For Self-Mint And Exchange

Use Vault policy boundaries as the primary control plane:

1. Grant `update` on `oci/exchange` only to trusted workloads that should use no-role or JWT-derived-role exchange, and grant `update` on specific `oci/exchange/<role>` paths when workloads should be limited to specific plugin roles.
2. Restrict role usage with path-based ACLs so each workload can only call specific role paths or namespaces.
3. Keep `enable_plugin_issued_subject_token=false` by default for general clients, and enable plugin-issued subject-token mode only for tightly scoped policies.
4. Use `subject_token_role_mappings` when callers provide their own JWTs and you want Vault role selection to come from trusted JWT claims rather than an explicit role path.
5. Treat plugin-issued self-mint as a separate trust model: OCI should rely on Vault-derived claims such as entity, alias, group, or namespace attributes, not the selected exchange role path. If you add `self_mint_custom_claims`, keep them additive and derive them only from trusted Vault context rather than caller-controlled request inputs.
6. Enable `strict_role_name_match=true` to prevent malformed role values.
7. Protect `oci/config` write access so only operators can rotate or replace self-mint settings and signing keys.
8. Treat `oci/exchange` as a privileged identity-issuance path when plugin-issued subject-token mode is enabled; do not grant it broadly just because OCI permissions are controlled later by service-user policy.
9. Expose `oci/jwks` as read-only to systems that need trust bootstrap; do not grant broader plugin capabilities with it.

Highly visible operator note:
- Vault policy on `oci/config` and `oci/exchange` is part of the security boundary for the self-minted flow. If those paths are too broadly accessible, callers may be able to mint Vault-backed subject tokens or alter the signing/trust configuration.

Vault enforces this with its normal path-based ACL policies. A common split is:

- operator/admin policy: can manage `oci/config` and `oci/role/*`
- workload policy: can call `oci/exchange` or selected `oci/exchange/<role>` paths but cannot read or write `oci/config`

Example workload policy:

```hcl
path "oci/exchange" {
  capabilities = ["create", "update"]
}

path "oci/exchange/developer" {
  capabilities = ["create", "update"]
}
```

Example operator policy:

```hcl
path "oci/config" {
  capabilities = ["create", "read", "update", "delete"]
}

path "oci/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

## Development

### Project Structure

```
.
├── oci-backend/
│   ├── backend.go          # Backend factory and configuration
│   ├── path_config.go      # Configuration management
│   ├── path_exchange.go    # Token exchange endpoint
│   ├── path_roles.go       # Role management
│   └── oci_client.go       # OCI API integration and JWT validation
├── main.go                 # Plugin entry point
├── go.mod                  # Go module definition
├── Makefile                # Build automation
└── README.md               # This file
```

### Running Tests

```bash
make test
```

### Local Development with Vault

Please refer to the [Contributing Guide](CONTRIBUTING.md#testing-locally-with-vault) for detailed instructions on how to start a local Vault dev server, test the plugin, and use the provided helper scripts.

## TODO / Future Enhancements

The maintained project backlog lives in [TODO.md](TODO.md).

Current highlights:
- metrics and telemetry
- OCI sandbox end-to-end integration tests
- self-mint key rotation and multi-key JWKS publication

## References

- [HashiCorp Vault Plugin Documentation](https://developer.hashicorp.com/vault/docs/plugins)
- [OCI Identity Domains](https://docs.oracle.com/en-us/iaas/Content/Identity/home.htm)
- [OCI IAM Federated Identity](https://docs.oracle.com/en-us/iaas/Content/Identity/federation/overview.htm)
- [OCI JWT to UPST Token Exchange](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm#jwt_token_exchange__get-oci-upst)
- [OAuth 2.0 Token Exchange RFC](https://tools.ietf.org/html/rfc8693)
- [Vault Secrets Engine Tutorial](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine)

## License

MIT License - See LICENSE file for details

## Contributing

Please see our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct, branching strategy, semantic versioning, and the process for submitting pull requests to us.

## Support

For issues and questions, please open a GitHub issue or contact the maintainers.
