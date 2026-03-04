# HashiCorp Vault OCI Secrets Engine

A HashiCorp Vault secrets engine plugin that exchanges 3rd party OIDC/OAuth JWT tokens for Oracle Cloud Infrastructure (OCI) session tokens.

## Overview

This plugin enables **federated identity** workflows by allowing users to exchange JWT tokens from external Identity Providers (IdPs) for temporary OCI session tokens. This eliminates the need to store long-lived OCI API keys in Vault.

### Architecture

```
┌─────────────────┐          ┌──────────────────┐          ┌─────────────────┐
│   External IdP  │          │   Vault Plugin   │          │   OCI IAM       │
│  (Auth0, Okta,  │          │                  │          │                 │
│   Azure AD,     │          │                  │          │                 │
│   etc.)         │          │                  │          │                 │
└────────┬────────┘          └────────┬─────────┘          └────────┬────────┘
         │                            │                             │
         │ 1. Issue JWT               │                             │
         │◄─────────────────          │                             │
         │                            │                             │
         │ 2. Submit JWT for exchange │                             │
         ├────────────────────────────►                             │
         │                            │                             │
         │                            │ 3. Validate & Exchange      │
         │                            ├─────────────────────────────►
         │                            │                             │
         │                            │ 4. Return OCI Session Token │
         │                            │◄────────────────────────────┤
         │                            │                             │
         │ 5. Return OCI credentials  │                             │
         │◄───────────────────────────┤                             │
         │                            │                             │
```

## Features

- **JWT Token Exchange**: Exchange OIDC/OAuth tokens for OCI session tokens
- **Vault Enterprise WIF Support**: Automatically fetch identity tokens via Vault's Workload Identity Federation plugin when running on Vault Enterprise (no `subject_token` required)
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
    max_ttl=28800
```

**Parameters:**
- `tenancy_ocid`: The OCID of your OCI tenancy
- `domain_url`: OCI Identity Domain URL (for example: `https://idcs-xxxxx.identity.oraclecloud.com`)
- `client_id`: OAuth Confidential Application client ID in the OCI Identity Domain
- `client_secret`: OAuth Confidential Application client secret in the OCI Identity Domain
- `region`: The OCI region (e.g., `us-ashburn-1`, `eu-frankfurt-1`)
- `default_ttl`: Default TTL for OCI session tokens in seconds (default: 3600)
- `max_ttl`: Maximum TTL for OCI session tokens in seconds (default: 86400)

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
    role="developer" \
    ttl=3600
```

*Note: If running on Vault Enterprise, `subject_token` is optional. The plugin will automatically fetch the Vault native Workload Identity Federation (WIF) plugin identity token if the `subject_token` is omitted.*

**Response:**
```json
{
  "data": {
    "access_token": "eyJ...",
    "session_token": "Atbv...",
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

### Using with OCI CLI

```bash
# Get credentials from Vault
CREDS=$(vault write -format=json oci/exchange subject_token="$JWT" role="developer")

# Extract the session token
export OCI_CLI_AUTH=security_token
export OCI_CLI_SECURITY_TOKEN=$(echo $CREDS | jq -r '.data.session_token')
export OCI_CLI_REGION=$(echo $CREDS | jq -r '.data.region')

# Use OCI CLI
oci iam user list
```

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
  "role": "developer",
  "ttl": 3600
}
```
*(Note: `subject_token` is optional on Vault Enterprise when utilizing WIF plugin identity tokens)*

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
5. **OCI returns** a session token
6. **Plugin returns** credentials to user with Vault lease

### Security Considerations

- **Token Validation**: Subject token validation is performed by OCI IAM during token exchange
- **Short-lived Tokens**: OCI session tokens have configurable TTL (default 1 hour)
- **Lease Management**: Vault lease lifecycle is applied to issued secrets
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

1. Start Vault in dev mode:
```bash
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin
```

2. Configure and test the plugin:
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

vault write sys/plugins/catalog/secrets/oci \
    sha_256="$(sha256sum bin/vault-plugin-secrets-oci | cut -d' ' -f1)" \
    command="vault-plugin-secrets-oci"

vault secrets enable -path=oci oci
```

## TODO / Future Enhancements

- [ ] Complete OCI IAM token exchange API integration
- [ ] Add support for mTLS authentication with OCI
- [ ] Implement caching of JWKS with rotation
- [ ] Add support for token refresh (renewal)
- [ ] Implement custom claims mapping (IdP → OCI)
- [ ] Add support for multiple IdPs per backend
- [ ] Add metrics and telemetry (token exchange rate, latency)
- [ ] Implement token introspection endpoint
- [ ] Add support for OCI Cloud Shell integration
- [ ] Build integration tests with OCI sandbox

## References

- [HashiCorp Vault Plugin Documentation](https://developer.hashicorp.com/vault/docs/plugins)
- [OCI Identity Domains](https://docs.oracle.com/en-us/iaas/Content/Identity/home.htm)
- [OCI IAM Federated Identity](https://docs.oracle.com/en-us/iaas/Content/Identity/federation/overview.htm)
- [OAuth 2.0 Token Exchange RFC](https://tools.ietf.org/html/rfc8693)
- [Vault Secrets Engine Tutorial](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine)

## License

MIT License - See LICENSE file for details

## Contributing

Please see our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct, branching strategy, semantic versioning, and the process for submitting pull requests to us.

## Support

For issues and questions, please open a GitHub issue or contact the maintainers.
