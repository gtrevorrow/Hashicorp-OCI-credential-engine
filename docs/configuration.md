# Operator Configuration

[README](../README.md) · [Mode selection](../README.md#how-configuration-selects-the-mode) · [Mapping features](../README.md#mapping-features) · [Usage recipes](usage.md)

## OCI Federated Identity Setup

Before using the plugin, configure it with your OCI Identity Domain details:

```bash
# Send an owner-only JSON config file through stdin.
vault write oci/config - < /private/path/oci-config.json
```

The file should contain:

```json
{
  "domain_url": "https://idcs-xxxxx.identity.oraclecloud.com",
  "client_id": "<oauth-client-id>",
  "client_secret": "<oauth-client-secret>",
  "default_ttl": 3600,
  "max_ttl": 28800,
  "enable_plugin_issued_subject_token": false,
  "brokered_subject_token_enabled": false
}
```

This starts with direct caller-token exchange. Enable self-mint or brokered mode separately using the [mode recipes](usage.md). Examples containing placeholder secrets are illustrative: for real credentials, use owner-only JSON files or stdin rather than expanding secrets into command arguments. Do not log exchange responses. Configuration reads omit the client secret and signing private key.

## Configuration field reference

All fields below belong to `oci/config`. Defaults are implementation defaults; the README setup explicitly disables plugin-issued mode until it is needed.

### OCI connection and lease policy

| Field | Meaning and default |
|---|---|
| <a id="config-domain-url"></a>`domain_url` | OCI Identity Domain URL (for example: `https://idcs-xxxxx.identity.oraclecloud.com`) |
| <a id="config-client-id"></a>`client_id` | OAuth Confidential Application client ID in the OCI Identity Domain |
| <a id="config-client-secret"></a>`client_secret` | OAuth Confidential Application client secret in the OCI Identity Domain |
| <a id="config-default-ttl"></a>`default_ttl` | Default Vault lease TTL in seconds (default: 3600). Also selects the RPST duration before conversion to whole minutes for OCI's `rpst_exp`. |
| <a id="config-max-ttl"></a>`max_ttl` | Maximum Vault lease TTL in seconds (default: 86400). Also bounds the RPST duration before conversion to whole minutes; RPST has an additional 12-hour cap. |

### Mode selection and role routing

| Field | Meaning and default |
|---|---|
| <a id="config-brokered-subject-token-enabled"></a>`brokered_subject_token_enabled` | Enables explicit brokered mode for caller-supplied `subject_token` values (default: `false`) |
| <a id="config-enable-plugin-issued-subject-token"></a>`enable_plugin_issued_subject_token` | When true, plugin-issued subject-token mode is enabled when the caller omits `subject_token` (default: `true`) |
| <a id="config-subject-token-self-mint-enabled"></a>`subject_token_self_mint_enabled` | Enables built-in self-mint in plugin-issued subject-token mode when Vault identity-token generation is unavailable (default: `false`) |
| <a id="config-subject-token-role-mappings"></a>`subject_token_role_mappings` | Ordered JWT-claim rules selecting a Vault role in direct mode. Each rule has `claim`, `op` (`eq`, `co`, `sw`), `value`, and `role`. See [role mapping](usage.md#caller-supplied-subject-token-flow-jwt-claim-to-vault-role-mapping). |
| <a id="config-strict-role-name-match"></a>`strict_role_name_match` | When true, requires role names to match `[A-Za-z0-9._:-]+` (default: `false`) |

### Engine signing and Vault identity

| Field | Meaning and default |
|---|---|
| <a id="config-subject-token-self-mint-issuer"></a>`subject_token_self_mint_issuer` | Required when self-mint or brokered mode is enabled |
| <a id="config-subject-token-self-mint-audience"></a>`subject_token_self_mint_audience` | Audience for self-minted token (default: `urn:mace:oci:idcs`) |
| <a id="config-subject-token-self-mint-ttl-seconds"></a>`subject_token_self_mint_ttl_seconds` | TTL for self-minted token in seconds (default: `600`) |
| <a id="config-subject-token-self-mint-private-key"></a>`subject_token_self_mint_private_key` | Optional PEM RSA private key. If omitted while self-mint or brokered mode is enabled, the plugin generates one and stores it in Vault plugin storage |
| <a id="config-subject-token-allowed-audiences"></a>`subject_token_allowed_audiences` | Optional allowlist for request-level audience override in plugin-issued subject-token mode via `subject_token_audience`. Entries are trimmed and deduplicated; blank entries, values over 512 bytes, and control characters remaining after trimming are rejected on configuration writes, including partial updates. An empty list disables overrides. |
| <a id="config-subject-token-identity-alias-mount-accessor"></a>`subject_token_identity_alias_mount_accessor` | Explicit auth mount accessor for linked-alias claims; empty disables them. This does not attest the current login method. |

### Incoming brokered JWT trust

| Field | Meaning and default |
|---|---|
| <a id="config-brokered-subject-token-trust-type"></a>`brokered_subject_token_trust_type` | Required when brokered mode is enabled. Supported values: `oidc_discovery`, `jwks_url`, `jwks_json`, `public_keys` |
| <a id="config-brokered-subject-token-issuer"></a>`brokered_subject_token_issuer` | Required when brokered mode is enabled. This is the expected incoming `iss` claim and the OIDC discovery issuer when `brokered_subject_token_trust_type=oidc_discovery` |
| <a id="config-brokered-subject-token-allowed-audiences"></a>`brokered_subject_token_allowed_audiences` | Required non-empty audience allowlist for incoming brokered-token validation |
| <a id="config-brokered-subject-token-allowed-algs"></a>`brokered_subject_token_allowed_algs` | Required non-empty signing algorithm allowlist for incoming brokered-token validation. Supported values are RSA (`RS256`, `RS384`, `RS512`) and EC (`ES256`, `ES384`, `ES512`) |
| <a id="config-brokered-subject-token-clock-skew-seconds"></a>`brokered_subject_token_clock_skew_seconds` | Optional clock-skew tolerance for brokered `exp`, `nbf`, and `iat` validation (default: `0`) |
| <a id="config-brokered-subject-token-jwks-url"></a>`brokered_subject_token_jwks_url` | Required when `brokered_subject_token_trust_type=jwks_url`; must use HTTPS unless loopback-only debug HTTP is explicitly enabled |
| <a id="config-brokered-subject-token-allowed-jwks-origins"></a>`brokered_subject_token_allowed_jwks_origins` | Additional exact origins (`https://host[:port]`, no path) allowed for discovered JWKS URLs hosted separately from the issuer. The issuer origin is allowed automatically |
| <a id="config-brokered-subject-token-jwks-json"></a>`brokered_subject_token_jwks_json` | Required when `brokered_subject_token_trust_type=jwks_json` |
| <a id="config-brokered-subject-token-public-keys"></a>`brokered_subject_token_public_keys` | Required when `brokered_subject_token_trust_type=public_keys`; accepts one PEM public key or a JSON array of PEM public keys |

### Brokered claim mapping

| Field | Meaning and default |
|---|---|
| <a id="config-brokered-subject-token-claim-mappings"></a>`brokered_subject_token_claim_mappings` | Optional JSON object of output-claim to string template. Templates may reference validated incoming claims such as `{{ claims.sub }}` or `svc/{{ claims.org }}/{{ claims.user.id }}` |

### Development diagnostics

| Field | Meaning and default |
|---|---|
| <a id="config-debug-allow-brokered-http"></a>`debug_allow_brokered_http` | Defaults to `false`. Allows HTTP trust retrieval only from `localhost` or loopback IP literals for local testing; it does not disable HTTPS certificate verification |
| <a id="config-debug-return-resolved-subject-token-claims"></a>`debug_return_resolved_subject_token_claims` | Defaults to `false`. Explicitly writing `true` permits decoded resolved-token claims in exchange responses, including OCI error responses, for 15 minutes; writing `false` disables them. See [diagnostic behavior](security-logging.md#temporary-claim-diagnostics). |
| <a id="config-debug-resolved-subject-token-claims-expires-at"></a>`debug_resolved_subject_token_claims_expires_at` | Read-only persisted diagnostic deadline (RFC3339), returned when set. Config reads report the effective diagnostic flag as `false` after expiry; unrelated writes and restarts do not renew the window. |

`oci/config` supports incremental updates. After the initial configuration is created, later `vault write oci/config ...` calls may update only the fields you want to change.

If `subject_token_self_mint_enabled=true`, OCI must be able to discover the published JWKS for the self-mint signing key. See [Self-Mint JWKS Publication Workflow](#self-mint-jwks-publication-workflow).

Brokered mode also relies on the existing self-mint signing configuration because the plugin re-issues a new JWT before calling OCI. Explicit `/oci/exchange/:role` requests are still allowed in brokered mode, but role contribution is limited to the existing TTL controls and additive templated `self_mint_custom_claims`. Existing `subject_token_role_mappings` remain part of the direct pass-through flow and are not reused in brokered mode.

## Brokered remote trust and key rotation

Remote discovery and JWKS retrieval require HTTPS by default. Discovery must return an `issuer` exactly equal to the configured issuer, including its path/trailing slash. A discovered JWKS URL must use the issuer origin or an explicitly configured `brokered_subject_token_allowed_jwks_origins` entry. Redirects are rejected, including redirects from the OCI token endpoint.

Trust retrieval uses direct connections rather than environment proxies. Resolved private, loopback, link-local, multicast, and unspecified addresses are rejected; the debug exception permits only loopback connections to `localhost` or loopback IP literals. DNS addresses are checked before dialing, and the checked IP is dialed directly. For private-network IdPs, use managed inline `jwks_json` or `public_keys`; this version does not provide a private-network remote-fetch override.

Discovery/JWKS documents and incoming brokered JWTs are limited to 1 MiB. Key sets are limited to 64 keys. Verification uses suitable public signing keys only: RSA at least 2048 bits or the EC curve required by the selected algorithm. The JOSE parser additionally limits RSA moduli in JWKs to 4096 bits and rejects excessive JSON nesting before signature verification. This JWK limit applies to inline and remote JWKS, and to embedded JWK headers; it does not change the explicit PEM `public_keys` parser. JWK `use`, `alg`, and `key_ops` metadata constrain key use. A JWT `kid` must select a matching JWKS key; explicit PEM `public_keys` have no key IDs and are tried against the signature independently of `kid`.

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

Within the 15-minute window, `vault write -force -format=json oci/exchange` includes decoded `resolved_subject_token_claims`, including on OCI rejection. These responses contain sensitive identity data. Explicitly disable the flag when finished. Existing stored `true` values without a deadline are inactive after upgrading until explicitly re-enabled. See [security logging and diagnostics](security-logging.md) for events, error redaction, audit settings, and the response-time expiry check.

## Multiple OCI Accounts or Identity Domains

This backend is designed around one OCI trust/config boundary per mount. A single mount has one `oci/config` entry, so it represents one OCI Identity Domain and one confidential application configuration at a time.

If you need to work with multiple OCI accounts, identity domains, or separate trust boundaries, mount the plugin multiple times at different paths. For example:

```bash
vault secrets enable -path=oci-dev -plugin-name=oci plugin
vault secrets enable -path=oci-prod -plugin-name=oci plugin
```

Then configure each mount separately with its own `oci/config` and roles.

## Roles

Create roles to define Vault lease policy and RPST TTL constraints. OCI UPST exchange does not currently let the client request token lifetime through the token-exchange call, so these TTL settings only directly shape the OCI request for RPST via `rpst_exp`. For UPST, they mainly affect Vault-side lease metadata today.

TTL selection uses an explicit positive request `ttl`, otherwise the role default, otherwise the backend default. An omitted or zero request `ttl` selects the default. The result is capped at the lowest positive backend maximum, role maximum, and effective Vault mount/system maximum returned by `SystemView.MaxLeaseTTL()`. A role can tighten the backend ceiling but cannot raise it. This applies to explicit and JWT-mapped roles and to every exchange mode. After exchange, Vault lease duration is additionally capped to known remaining OCI credential lifetime; OCI determines the lifetime actually granted.

Vault TTL inputs use seconds (or duration strings). OCI's RPST `rpst_exp` uses **whole minutes**, with a maximum of 720 minutes (12 hours). For RPST, the engine caps the effective TTL at 12 hours and rounds down to whole minutes before requesting OCI credentials and assigning the Vault lease. For example, `ttl=60` sends `rpst_exp=1`; `ttl=90` also sends `1` and selects a 60-second lease. An effective TTL below 60 seconds is rejected before OCI exchange, including when a role, backend, or Vault ceiling imposes that limit. The engine never rounds a lifetime up or sends zero to select an upstream default. UPST lease policy retains whole-second precision. See [Oracle's RPST request parameters](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange_grant_type_workload_id-federation.htm).

Backend and role `default_ttl`/`max_ttl` writes require positive whole-second durations with `default_ttl <= max_ttl`. Supported duration strings such as `1h` remain accepted. Zero, negative, fractional-second, and overflowing policy values are rejected. Each value is bounded to 9,223,372,036 seconds before nanosecond conversion. Request `ttl` uses the same range, with zero additionally allowed to select the default. A fractional Vault ceiling is rounded down to whole seconds; a positive ceiling below one second fails closed.

Examples of TTL validation and selection:

| Input or policy | Result |
|---|---|
| `default_ttl=60 max_ttl=600` | Valid policy |
| `default_ttl=3600 max_ttl=600` | Rejected: the policy's default exceeds its own maximum |
| Configured `default_ttl=0`, `max_ttl=-60`, or `default_ttl="500ms"` | Rejected; the stored configuration is unchanged |
| Request `ttl=0`, or no `ttl` | Select the role/backend default, then apply all ceilings |
| RPST effective TTL of 90 seconds | Request `rpst_exp=1` and select a 60-second Vault lease |
| RPST effective TTL below 60 seconds | Reject; no OCI exchange |
| RPST effective TTL above 12 hours | Request `rpst_exp=720` and cap the Vault lease at 12 hours |
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
- `default_ttl`: Default Vault lease TTL for credentials issued under the role. For RPST exchanges, the effective duration is converted from seconds to whole minutes for `rpst_exp`.
- `max_ttl`: Maximum Vault lease TTL for credentials issued under the role. Also bounds the RPST lifetime before conversion to whole minutes; it cannot raise OCI's 12-hour maximum.

## Removed role filter fields and upgrade cleanup

`allowed_subjects` and `allowed_groups` have been removed. They were stored metadata and never enforced authorization. They are no longer accepted role parameters, stored in new role records, or returned as role fields. Role writes now reject all unknown fields, including these two names even when their values are empty or null.

Existing stored roles with nonempty values (or malformed legacy values) require explicit cleanup. Reads return the supported fields plus a warning naming the removed fields; listing and deletion remain available. Exchange through an affected named or JWT-mapped role fails, and ordinary writes cannot silently overwrite it. Missing, empty-array, or null legacy values do not block role use.

Before upgrading, identify affected roles and review the actual Vault ACLs and OCI trust/authorization policies. To clean up an affected role:

1. Read and retain its supported configuration: description, default/max TTLs, and `self_mint_custom_claims`. Review the warning; the removed filters never supplied access protection.
2. Confirm the intended caller permissions are implemented through Vault and OCI controls. Direct `subject_token_role_mappings` remains supported and intentionally delegates role selection.
3. Explicitly delete the affected role with `vault delete oci/role/<name>`.
4. Recreate it with the retained supported parameters, omitting both removed fields. Role writes apply defaults to omitted values, so supply all settings you intend to retain.
5. Read it back and verify exchange with an authorized caller. The role is unavailable between deletion and recreation; coordinate that window with its consumers.

The plugin does not automatically delete or migrate nonempty removed settings, and no additional cleanup endpoint or bypass flag is provided. Subject/group filtering can be reconsidered only when a concrete use case defines the trusted identity and claims to constrain.

## Self-Mint JWKS Publication Workflow

If you enable built-in self-minting, the plugin can expose the signing public key as JWKS at `oci/jwks`. That Vault path is intended as an operator export point, not as the final OCI discovery URL.

Recommended workflow:

1. Configure self-mint on the plugin.
2. Read the JWKS from Vault:

```bash
vault read -format=json oci/jwks | jq '.data' > jwks.json
```

Publish the `data` object (`{"keys":[...]}`), not the Vault response envelope. The export currently requires `subject_token_self_mint_enabled=true`, including when using its key for brokered signing.

3. Publish that JWKS document to an HTTPS location OCI Identity Domains can reach, for example:
   - GitHub Pages
   - OCI Object Storage static website hosting
   - another normal HTTPS-hosted file
4. Configure OCI token exchange trust to use that published JWKS URL.
5. If the self-mint signing key changes, publish the updated JWKS before relying on newly minted tokens.

Security Note: It is important to strictly control who is allowed to update the JWKS since that is part of the trust boundary

## Local development settings

Use [CONTRIBUTING.md](../CONTRIBUTING.md#testing-locally-with-vault) for the local Vault lifecycle and security requirements. The settings below describe the optional configuration seeded by that workflow.

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

Dev Note: If JWT self-mint or brokered mode is enabled in `.env.local` and `OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY` is not set, `./scripts/dev_vault.sh start` will create and reuse a local ignored PEM file at `.vault-dev-self-mint-key.pem`. That keeps the self-mint JWKS stable across dev restarts.
