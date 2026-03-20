# HashiCorp Vault OCI Secrets Engine

A HashiCorp Vault secrets engine plugin that exchanges 3rd party OIDC/OAuth JWT tokens for Oracle Cloud Infrastructure (OCI) session tokens.

## Overview

This plugin enables **federated identity** workflows by allowing users to exchange JWT tokens from external Identity Providers (IdPs) for temporary OCI session tokens. This eliminates the need to store long-lived OCI API keys in Vault.

### Sequence Diagrams (Current Implemented Flows)

These diagrams describe the implemented request flows in the plugin.

Actor definitions used in diagrams:

- **Client/Workload**: The caller (app, CI job, script, or human) that invokes `vault write oci/exchange`.
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

    C->>V: `vault write oci/exchange` with `subject_token`
    V->>S: Read backend config and optional plugin role
    S-->>V: Config and role constraints
    V->>V: Validate request fields and TTL
    V->>V: If `subject_token_role_mappings` exist, derive Vault role from caller JWT
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    V->>O: POST `/oauth2/v1/token` with Basic auth, `subject_token_type=jwt`, `requested_token_type`, base64 SPKI `public_key`, optional `res_type`
    O-->>V: OCI UPST or RPST
    V-->>C: Vault secret response with OCI token, lease, and exchange keypair only when generated
```

Client sends `subject_token`; plugin validates role constraints/guardrails and performs token exchange against OCI.

#### 1.1) Caller JWT Role Mapping Variant

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange` with caller JWT
    V->>S: Read backend config and role policy
    S-->>V: `subject_token_role_mappings`, role entries
    V->>V: Parse caller JWT payload only
    V->>V: Evaluate ordered role-mapping rules
    V->>V: First matching rule selects Vault role
    V->>S: Read derived Vault role entry
    S-->>V: Role TTL and local policy constraints

    alt Mapping rule matches
        V->>O: POST `/oauth2/v1/token`
        O-->>V: OCI session token
        V-->>C: Success response
    else No rule matches
        V-->>C: Error response before OCI call
    end
```

This is a caller-supplied `subject_token` variant of flow 1. When `subject_token_role_mappings` are configured, the engine derives the effective Vault role from trusted JWT claims before OCI exchange instead of relying on a caller-supplied `role`.

#### 2) Exchange Without `subject_token` (Plugin-Issued Subject Token Mode)

```mermaid
sequenceDiagram
    autonumber
    actor C as Client / Workload
    participant V as Vault OCI Credential Engine
    participant S as Vault Storage
    participant SV as Vault System View
    participant O as OCI Token Endpoint

    C->>V: `vault write oci/exchange` without `subject_token`
    V->>S: Read backend config and optional plugin role
    S-->>V: Config and role constraints
    V->>V: Check `enable_plugin_issued_subject_token=true`
    V->>V: Resolve audience from config or allowlisted `subject_token_audience`
    V->>SV: `GenerateIdentityToken(audience)`
    SV-->>V: Vault-issued identity token
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    V->>O: POST `/oauth2/v1/token` with Basic auth, `subject_token_type=jwt`, `requested_token_type`, base64 SPKI `public_key`, optional `res_type`
    O-->>V: OCI UPST or RPST
    V-->>C: Vault secret response with OCI token, lease, and exchange keypair only when generated
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

    C->>V: `vault write oci/exchange` without `subject_token`
    V->>S: Read backend config and self-mint key
    S-->>V: Config, role constraints, signing key
    V->>V: Check plugin-issued mode is enabled
    V->>V: Resolve audience from config or allowlisted `subject_token_audience`
    V->>SV: `GenerateIdentityToken(audience)`
    SV-->>V: Identity token unavailable
    V->>SV: Read trusted Vault request and identity context
    SV-->>V: Entity, alias, group, mount metadata
    V->>V: Build JWT with Vault-derived claims
    V->>V: Sign self-minted JWT with plugin signing key
    alt Caller supplies `public_key`
        V->>V: Use caller public key for OCI exchange
    else `public_key` omitted
        V->>V: Generate exchange RSA keypair
    end
    V->>O: POST `/oauth2/v1/token` with Basic auth, self-minted `subject_token`, `subject_token_type=jwt`, `requested_token_type`, base64 SPKI `public_key`, optional `res_type`
    O-->>V: OCI UPST or RPST
    V-->>C: Vault secret response with OCI token, lease, and exchange keypair only when generated
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
- **Returned OCI Key Pair**: Exchange responses can include Credential Engine generated PEM-encoded `private_key` and `public_key` for request-signing workflows
- **Plugin-Issued Subject Token Mode**: If `subject_token` is omitted and `enable_plugin_issued_subject_token=true`, the plugin resolves a token itself (default callback: Vault identity token first if availble in the version of vualt, self-mint if configured)
- **Role-based TTL Policies**: Define roles with default and maximum TTL constraints
- **Lease Management**: OCI tokens are issued as Vault secrets with TTL-based lease handling


## Prerequisites

- Go 1.21 or later
- HashiCorp Vault 1.12+ (dev mode or server mode)
- OCI tenancy with Identity Domain configured
- External Identity Provider (IdP) integrated with OCI IAM

## Installation

### Build the Plugin

```bash
# Clone the repository
git clone https://github.com/gordon/Hashicorp-OCI-credential-engine.git
cd Hashicorp-OCI-credential-engine

# Download dependencies
go mod tidy

# Build the plugin
make build

# Or build for all platforms
make build-all
```

### Register the Plugin with Vault

For local development, `./scripts/dev_vault.sh start` now starts Vault dev mode, registers the plugin, enables the `oci` mount automatically, and can seed `oci/config` from a local `.env.local` file in the repo root. The manual steps below are still useful for non-dev setups and for understanding the underlying Vault operations.

If you want dev startup to reapply backend config automatically, create `.env.local` in the repo root with at least:

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
- `OCI_SUBJECT_TOKEN_SELF_MINT_ENABLED`
- `OCI_SUBJECT_TOKEN_SELF_MINT_ISSUER`
- `OCI_SUBJECT_TOKEN_SELF_MINT_AUDIENCE`
- `OCI_SUBJECT_TOKEN_SELF_MINT_TTL_SECONDS`
- `OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY`
- `OCI_DEBUG_RETURN_RESOLVED_SUBJECT_TOKEN_CLAIMS`

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
    subject_token_allowed_audiences="urn:oci:test,urn:oci:prod"
```

**Parameters:**
- `domain_url`: OCI Identity Domain URL (for example: `https://idcs-xxxxx.identity.oraclecloud.com`)
- `client_id`: OAuth Confidential Application client ID in the OCI Identity Domain
- `client_secret`: OAuth Confidential Application client secret in the OCI Identity Domain
- `default_ttl`: Default Vault lease TTL for exchanged credentials, and the default requested TTL for RPST exchanges when a request TTL is not supplied (default: 3600)
- `max_ttl`: Maximum Vault lease TTL for exchanged credentials, and the maximum requested TTL allowed for RPST exchanges (default: 86400)
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
- `subject_token_allowed_audiences`: Optional allowlist for request-level audience override in plugin-issued subject-token mode via `subject_token_audience`
- `subject_token_self_mint_ttl_seconds`: TTL for self-minted token in seconds (default: `600`)
- `subject_token_self_mint_private_key`: Optional PEM RSA private key. If omitted while self-mint is enabled, the plugin generates one and stores it in Vault plugin storage
- `debug_return_resolved_subject_token_claims`: Development-only flag that includes decoded claims from the resolved subject token in `oci/exchange` responses, including error responses

If `subject_token_self_mint_enabled=true`, OCI must be able to discover the published JWKS for the self-mint signing key. See [Self-Mint JWKS Publication Workflow](#self-mint-jwks-publication-workflow).

The plugin keeps the private signing key in Vault plugin storage. The published JWKS contains only the public key material.

For local debugging of plugin-issued subject tokens, you can temporarily enable:

```bash
vault write oci/config \
    domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..xxxxx" \
    client_secret="<oauth-client-secret>" \
    subject_token_self_mint_enabled=true \
    subject_token_self_mint_issuer="https://vault.example.com" \
    debug_return_resolved_subject_token_claims=true
```

Then `vault write -force -format=json oci/exchange` will include `data.resolved_subject_token_claims` even when OCI rejects the exchange. This flag is intended only for development and troubleshooting.

### Roles

Create roles to define Vault lease policy and RPST TTL constraints. OCI UPST exchange does not currently let the client request token lifetime through the token-exchange call, so these TTL settings only directly shape the OCI request for RPST. For UPST, they mainly affect Vault-side lease metadata today.

```bash
# Create a development role
vault write oci/roles/developer \
    description="Development environment access" \
    default_ttl=3600 \
    max_ttl=14400 \
    allowed_groups="dev-team,engineering" \
    allowed_subjects="user1@example.com,user2@example.com"

# Create a production role with stricter controls
vault write oci/roles/prod \
    description="Production environment access" \
    default_ttl=1800 \
    max_ttl=3600 \
    allowed_groups="sre-team"
```

**Role Parameters:**
- `default_ttl`: Default Vault lease TTL for credentials issued under the role. Intended to also be the default requested TTL for RPST exchanges when a request TTL is not supplied.
- `max_ttl`: Maximum Vault lease TTL for credentials issued under the role. Intended to also be the maximum requested TTL allowed for RPST exchanges.
- `allowed_groups`: Stored role metadata for future claim filtering
- `allowed_subjects`: Stored role metadata for future subject filtering

## Usage

### Exchange a JWT for OCI Credentials

```bash
vault write oci/exchange \
    subject_token="eyJhbGciOiJSUzI1NiIs..." \
    requested_token_type="urn:oci:token-type:oci-upst" \
    ttl=3600
```

Notes:

- Omit `subject_token` and set `enable_plugin_issued_subject_token=true` if you want the credential engine to obtain one on the caller's behalf. On Vault Enterprise, the engine first tries Vault identity-token generation. On Vault Open Source, or if Vault cannot generate an identity token for the request, the engine can fall back to self-mint when `subject_token_self_mint_enabled=true` and the required self-mint settings are configured.
- If the credential engine obtains a subject token on the caller's behalf, the caller may optionally provide `subject_token_audience`. That override is accepted only when the requested value is listed in `subject_token_allowed_audiences`.
- If the caller supplies `subject_token`, the caller may provide `role` only when `subject_token_role_mappings` are not configured. When mappings are configured, the engine derives the effective Vault role from JWT claims and rejects caller-supplied `role`.
- If `public_key` is not supplied, the engine generates a fresh RSA key pair for the exchange.

*Reference: Oracle JWT-to-UPST flow and request parameters are documented in [Token Exchange Grant Type: Exchanging a JSON Web Token for a UPST](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm#jwt_token_exchange__get-oci-upst).*

**Response:**
```json
{
  "data": {
    "access_token": "eyJ...",
    "session_token": "Atbv...",
    "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE...",
    "public_key": "-----BEGIN PUBLIC KEY-----\\nMIIB...",
    "requested_token_type": "urn:oci:token-type:oci-upst",
    "token_type": "Bearer",
    "expires_in": 3600,
    "expires_at": "2024-01-15T10:30:00Z"
  },
  "lease_id": "oci/exchange/...",
  "lease_duration": 3600,
  "renewable": true
}
```

If `public_key` is provided in the request, the plugin will not return `private_key` or `public_key` in the response.
This applies to both caller-supplied `subject_token` mode and plugin-issued self-mint mode: if the caller supplies `public_key`, the plugin uses that key in the OCI token exchange payload and does not generate or return an exchange key pair.

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
- When `subject_token_role_mappings` is configured, callers must omit the request `role`; the plugin derives it from the JWT instead.
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

Example Vault-issued JWT setup:

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

# Create token role that emits claim used by OCI trust rules
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
    requested_token_type="urn:oci:token-type:oci-upst" \
    role="developer"
```

5. OCI Identity Domain token exchange trust evaluates issuer/audience/claims and maps to the target OCI Domain Service User. OCI IAM policies on that service user determine final permissions.

See [DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md](DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md) for full architecture and implementation details.

*Important: No-`subject_token` flow uses plugin-issued subject-token mode and depends on `enable_plugin_issued_subject_token=true`. With the default callback, Vault identity-token generation is attempted first; if unavailable, self-mint is used only when explicitly configured. Self-minted tokens use Vault-derived identity claims, not the request `role`.*

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
- The request `role` is not copied into the self-minted JWT.
- `aud` defaults to plugin config (`subject_token_self_mint_audience`) and may be overridden per request only through allowlisted `subject_token_audience` values.
- OCI trust rules should use the Vault-derived claims above rather than caller-supplied parameters.
- When the caller request is backed by a Vault Identity entity, `vault_entity_id` is the preferred stable trust-mapping claim.
- When the caller is using a token flow without an attached entity, the self-minted JWT still includes token-context claims such as `vault_display_name`, `vault_mount_accessor`, `vault_mount_type`, and `vault_client_token_accessor`, and OCI trust can map on those if needed.
- Claims like `vault_display_name` and `vault_client_token_accessor` are a weaker trust anchor than `vault_entity_id` because they identify token context rather than a durable Vault identity. Prefer `vault_entity_id` whenever it is available.

### Using with OCI CLI

```bash
# Get credentials from Vault
CREDS=$(vault write -format=json oci/exchange subject_token="$JWT" role="developer")

# Extract the session token
export OCI_CLI_AUTH=security_token
export OCI_CLI_SECURITY_TOKEN=$(echo $CREDS | jq -r '.data.session_token')

# Persist key material returned by the plugin
mkdir -p ~/.oci
echo "$CREDS" | jq -r '.data.private_key' > ~/.oci/key.pem
echo "$CREDS" | jq -r '.data.public_key' > ~/.oci/key_public.pem
chmod 600 ~/.oci/key.pem

# Use OCI CLI
oci iam user list
```

The `private_key` and `public_key` fields are PEM-encoded and can be used by tools or SDK wrappers that require explicit key material for OCI request signing, which aligns with OCI's UPST public-key workflow. Treat `private_key` as sensitive secret material.

### Exchange a JWT for OCI RPST

Use RPST when you need resource-principal style token exchange behavior supported by OCI Identity Domains.

```bash
vault write oci/exchange \
    subject_token="eyJhbGciOiJSUzI1NiIs..." \
    requested_token_type="urn:oci:token-type:oci-rpst" \
    res_type="resource_principal" \
    role="developer"
```

For RPST requests, `res_type` is required and the response will include `rpst_token`.

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
| `POST/PUT` | `/oci/exchange` | Exchange JWT subject token for OCI credentials |

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
  "role": "developer",
  "ttl": 3600
}
```
*(Note: `subject_token` is optional when `enable_plugin_issued_subject_token=true` and the plugin-issued subject-token mode can resolve a token. `subject_token_audience` is only used for plugin-issued subject tokens. The plugin always sends `subject_token_type=jwt` to OCI.)*

`requested_token_type` defaults to `urn:oci:token-type:oci-upst`. Supported values:
- `urn:oci:token-type:oci-upst`
- `urn:oci:token-type:oci-rpst` (requires `res_type`)

TTL note:
- For RPST, the plugin uses config and role TTL policy to bound the requested lifetime sent to OCI.
- For UPST, OCI determines the token lifetime; plugin TTL settings affect Vault lease metadata, not OCI-side UPST expiration.

### Roles Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/roles/:name` | Read a role |
| `POST/PUT` | `/oci/roles/:name` | Create or update a role |
| `DELETE` | `/oci/roles/:name` | Delete a role |
| `LIST` | `/oci/roles` | List all roles |

## Architecture Details

### Token Exchange Flow

1. **User authenticates** with external IdP and receives JWT
2. **User submits JWT** to Vault plugin's `/exchange` endpoint
3. **Plugin calls OCI IAM** token exchange API
4. **OCI validates** the JWT against the federated IdP
5. **OCI returns** the requested token type (UPST or RPST)
6. **Plugin returns** credentials to user with Vault lease

### Security Considerations

- **Token Validation**: Subject token validation is performed by OCI IAM during token exchange
- **TTL Semantics**: RPST requests can be bounded by plugin TTL policy. UPST lifetime is determined by OCI; plugin TTL settings mainly control Vault lease metadata for UPST responses.
- **Lease Management**: Vault lease lifecycle is applied to issued secrets, but OCI exchanged tokens cannot be actively revoked server-side before expiration. Vault simply drops the lease locally.
- **Audit Logging**: All token exchanges are logged to Vault audit log
- **Self-Mint Key Handling**: When `subject_token_self_mint_enabled=true` and no private key is supplied, the plugin generates an RSA key pair and persists the private key in plugin storage. The key is never returned by `read oci/config`.

### Access Controls For Self-Mint And Exchange

Use Vault policy boundaries as the primary control plane:

1. Grant `update` on `oci/exchange` only to trusted workloads.
2. Restrict role usage with path-based ACLs so each workload can only call specific role paths or namespaces.
3. Keep `enable_plugin_issued_subject_token=false` by default for general clients, and enable plugin-issued subject-token mode only for tightly scoped policies.
4. Use `subject_token_role_mappings` when callers provide their own JWTs and you want Vault role selection to come from trusted JWT claims rather than a caller-supplied `role` parameter.
5. Treat plugin-issued self-mint as a separate trust model: OCI should rely on Vault-derived claims such as entity, alias, group, or namespace attributes, not the request `role`.
6. Enable `strict_role_name_match=true` to prevent malformed role values.
7. Protect `oci/config` write access so only operators can rotate or replace self-mint settings and signing keys.
8. Treat `oci/exchange` as a privileged identity-issuance path when plugin-issued subject-token mode is enabled; do not grant it broadly just because OCI permissions are controlled later by service-user policy.
9. Expose `oci/jwks` as read-only to systems that need trust bootstrap; do not grant broader plugin capabilities with it.

Highly visible operator note:
- Vault policy on `oci/config` and `oci/exchange` is part of the security boundary for the self-minted flow. If those paths are too broadly accessible, callers may be able to mint Vault-backed subject tokens or alter the signing/trust configuration.

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

The maintained project backlog lives in [TODO.md](/Users/gordon/Documents/projects/Hashicorp-OCI-credential-engine/TODO.md).

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
