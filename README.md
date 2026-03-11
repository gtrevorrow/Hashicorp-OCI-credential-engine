# HashiCorp Vault OCI Secrets Engine

A HashiCorp Vault secrets engine plugin that exchanges 3rd party OIDC/OAuth JWT tokens for Oracle Cloud Infrastructure (OCI) session tokens.

## Overview

This plugin enables **federated identity** workflows by allowing users to exchange JWT tokens from external Identity Providers (IdPs) for temporary OCI session tokens. This eliminates the need to store long-lived OCI API keys in Vault.

### Sequence Diagrams (Current Implemented Flows)

These diagrams describe the implemented request flows in the plugin.

Actor definitions used in diagrams:

- **Client/Workload**: The caller (app, CI job, script, or human) that invokes `vault write oci/exchange`.
- **Vault OCI Plugin**: This secrets-engine plugin instance mounted in Vault.
- **Vault Storage**: Plugin storage view used for reading config and role entries.
- **Vault System View**: Vault runtime interface available to plugins; used here for plugin identity token minting (`GenerateIdentityToken`) when fallback is allowed.
- **OCI Token Endpoint**: OCI Identity Domain OAuth token exchange endpoint (`/oauth2/v1/token`).

#### 1) Standard Exchange (Caller Provides `subject_token`)

![Standard Exchange Diagram](./assets/diagram-1.svg)

#### 2) Exchange Without `subject_token` (Plugin Identity Fallback)

![Exchange Without subject_token (Plugin Identity Fallback)](./assets/diagram-2.svg)

#### 3) Role-Claim Guardrail and Strict Role Name Validation

![Role-Claim Guardrail and Strict Role Name Validation](./assets/diagram-3.svg)

### Terminology
When referring to token exchanges in this plugin, we use standard OAuth 2.0 (RFC 8693) and OCI Identity nomenclature:

- **Subject Token**: The initial JWT (JSON Web Token) provided by an external Identity Provider (e.g., Auth0, Azure AD, Okta, Vault Enterprise WIF). This is the token that proves the user's or workload's identity.
- **Token Exchange**: The process of trading the *Subject Token* for an OCI-specific token. The plugin acts as the intermediary, securely presenting the Subject Token to OCI over the `urn:ietf:params:oauth:grant-type:token-exchange` grant type.
- **UPST (User Principal Session Token)**: The resulting session token issued by Oracle Cloud Infrastructure. Once the exchange succeeds, OCI returns a UPST. This token is what the end-user or workload actually uses to authenticate API calls against OCI services.

## Features

- **JWT Token Exchange**: Exchange OIDC/OAuth tokens for OCI session tokens
- **UPST and RPST Support**: Request either `urn:oci:token-type:oci-upst` or `urn:oci:token-type:oci-rpst`
- **Returned OCI Key Pair**: Exchange responses include PEM-encoded `private_key` and `public_key` for request-signing workflows
- **Vault Enterprise WIF Support**: Automatically fetch identity tokens via Vault's Workload Identity Federation/plugin identity-token capabilities when running on Vault Enterprise (no `subject_token` required)
- **Federated Identity**: Leverage OCI IAM Identity Domains with external IdPs
- **Role-based TTL Policies**: Define roles with default and maximum TTL constraints
- **Lease Management**: OCI tokens are issued as Vault secrets with TTL-based lease handling
- **Multi-tenant Support**: Support for multiple OCI Identity Domains and regions

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

1. Calculate the SHA256 checksum of the plugin binary:
```bash
sha256sum bin/vault-plugin-secrets-oci
```

2. Register the plugin in Vault's catalog:
```bash
# If using a local dev server, ensure VAULT_ADDR is set to http
export VAULT_ADDR='http://127.0.0.1:8200'

vault write sys/plugins/catalog/secrets/oci \
    sha_256="<SHA256_CHECKSUM>" \
    command="vault-plugin-secrets-oci"
```

3. Enable the secrets engine:
```bash
vault secrets enable -path=oci oci
```

## Configuration

### OCI Federated Identity Setup

Before using the plugin, configure it with your OCI Identity Domain details:

```bash
vault write oci/config \
    tenancy_ocid="ocid1.tenancy.oc1..xxxxx" \
    domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..xxxxx" \
    client_secret="<oauth-client-secret>" \
    region="us-ashburn-1" \
    default_ttl=3600 \
    max_ttl=28800 \
    enforce_role_claim_match=false \
    role_claim_key="vault_role"
```

**Parameters:**
- `tenancy_ocid`: The OCID of your OCI tenancy
- `domain_url`: OCI Identity Domain URL (for example: `https://idcs-xxxxx.identity.oraclecloud.com`)
- `client_id`: OAuth Confidential Application client ID in the OCI Identity Domain
- `client_secret`: OAuth Confidential Application client secret in the OCI Identity Domain
- `region`: The OCI region (e.g., `us-ashburn-1`, `eu-frankfurt-1`)
- `default_ttl`: Default TTL for OCI session tokens in seconds (default: 3600)
- `max_ttl`: Maximum TTL for OCI session tokens in seconds (default: 86400)
- `enforce_role_claim_match`: When true, requires a caller-provided `subject_token` claim to match the requested plugin role (default: `false`)
- `role_claim_key`: JWT claim key used for role matching when enforcement is enabled (default: `vault_role`)

### Roles

Create roles to define token TTL constraints:

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
- `allowed_groups`: Stored role metadata for future claim filtering
- `allowed_subjects`: Stored role metadata for future subject filtering

## Usage

### Exchange a JWT for OCI Credentials

```bash
vault write oci/exchange \
    subject_token="eyJhbGciOiJSUzI1NiIs..." \
    subject_token_type="urn:ietf:params:oauth:token-type:jwt" \
    requested_token_type="urn:oci:token-type:oci-upst" \
    role="developer" \
    ttl=3600
```

*Note: Omitting `subject_token` requires Vault Enterprise WIF/plugin identity-token support. In OSS or environments where this capability is unavailable, provide `subject_token` explicitly.*

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
    "expires_at": "2024-01-15T10:30:00Z",
    "region": "us-ashburn-1",
    "tenancy_ocid": "ocid1.tenancy.oc1..xxxxx"
  },
  "lease_id": "oci/exchange/...",
  "lease_duration": 3600,
  "renewable": true
}
```

If `public_key` is provided in the request, the plugin will not return `private_key` or `public_key` in the response.

### Vault-Issued Subject Token Flow (Role to OCI Principal Mapping)

Use this flow when OCI trust rules should map Vault-issued token claims (for example `vault_role` or `oci_target`) to OCI Domain Service Users.

1. Configure plugin role-claim guardrail (optional but recommended):

```bash
vault write oci/config \
    tenancy_ocid="ocid1.tenancy.oc1..xxxxx" \
    domain_url="https://idcs-xxxxx.identity.oraclecloud.com" \
    client_id="ocid1.oauth2client.oc1..xxxxx" \
    client_secret="<oauth-client-secret>" \
    region="us-ashburn-1" \
    default_ttl=3600 \
    max_ttl=28800 \
    enforce_role_claim_match=true \
    role_claim_key="vault_role"
```

2. In Vault Identity/OIDC, define a token role that emits a mapping claim (example: `vault_role=developer`) and allow workloads to mint from it.

Example Vault setup:

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
    subject_token_type="urn:ietf:params:oauth:token-type:jwt" \
    requested_token_type="urn:oci:token-type:oci-upst" \
    role="developer"
```

5. OCI Identity Domain token exchange trust evaluates issuer/audience/claims and maps to the target OCI Domain Service User. OCI IAM policies on that service user determine final permissions.

See [DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md](DESIGN_VAULT_ROLE_TO_OCI_SERVICE_USER.md) for full architecture and implementation details.

*Important: The no-`subject_token` fallback path in this plugin depends on Vault Enterprise plugin identity-token/WIF support. If unavailable, clients must send `subject_token` on each exchange request.*

### Using with OCI CLI

```bash
# Get credentials from Vault
CREDS=$(vault write -format=json oci/exchange subject_token="$JWT" role="developer")

# Extract the session token
export OCI_CLI_AUTH=security_token
export OCI_CLI_SECURITY_TOKEN=$(echo $CREDS | jq -r '.data.session_token')
export OCI_CLI_REGION=$(echo $CREDS | jq -r '.data.region')

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
    subject_token_type="urn:ietf:params:oauth:token-type:jwt" \
    requested_token_type="urn:oci:token-type:oci-rpst" \
    res_type="resource_principal" \
    role="developer"
```

For RPST requests, `res_type` is required and the response will include `rpst_token`.

### Using with OCI SDK (Go)

```go
import (
    "github.com/oracle/oci-go-sdk/v65/common"
    "github.com/oracle/oci-go-sdk/v65/identity"
)

// Exchange token via Vault API
// Then use the returned session token
configProvider := common.NewRawConfigurationProvider(
    tenancyOCID,
    "", // user OCID not needed for session token
    region,
    "", // fingerprint not needed
    "", // private key not needed
    nil,
)

// Set up authentication with session token
// (Implementation depends on OCI SDK version)
```

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

**Request Body:**
```json
{
  "subject_token": "eyJhbGciOiJSUzI1NiIs...",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "requested_token_type": "urn:oci:token-type:oci-upst",
    "res_type": "resource_principal",
    "public_key": "-----BEGIN PUBLIC KEY-----...",
  "role": "developer",
  "ttl": 3600
}
```
*(Note: `subject_token` is optional on Vault Enterprise when utilizing WIF plugin identity tokens)*

`requested_token_type` defaults to `urn:oci:token-type:oci-upst`. Supported values:
- `urn:oci:token-type:oci-upst`
- `urn:oci:token-type:oci-rpst` (requires `res_type`)

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
- **Short-lived Tokens**: OCI exchanged tokens have configurable TTL (default 1 hour)
- **Lease Management**: Vault lease lifecycle is applied to issued secrets, but OCI exchanged tokens cannot be actively revoked server-side before expiration. Vault simply drops the lease locally.
- **Audit Logging**: All token exchanges are logged to Vault audit log

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

### Current Scope (OCI Identity Domain is the JWT validation authority)

- [x] Complete OCI IAM token exchange API integration
- [ ] Optimize re-issuance flow for obtaining new UPST/RPST tokens before expiry
- [ ] Add metrics and telemetry (token exchange rate, latency)
- [ ] Build integration tests with OCI sandbox

### Optional Future Mode (Plugin-issued subject tokens, WIF-style)

- [ ] Add optional mode where the plugin issues subject tokens trusted by OCI Identity Domains
- [ ] Publish JWKS for OCI trust configuration and key rotation
- [ ] Add support for multiple issuers/IdPs per backend in plugin-issued token mode
- [ ] Implement claims mapping/policy translation for plugin-issued tokens
- [ ] Evaluate OCI Cloud Shell integration for plugin-issued token workflows

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
