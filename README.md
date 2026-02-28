# HashiCorp Vault OCI Secrets Engine

A HashiCorp Vault secrets engine plugin that dynamically generates Oracle Cloud Infrastructure (OCI) session tokens.

## Overview

This plugin integrates with HashiCorp Vault to provide on-demand OCI authentication tokens. Instead of storing long-lived OCI API keys, you can use Vault to generate short-lived session tokens with configurable TTLs.

## Features

- **Dynamic token generation**: Create OCI session tokens on-demand with configurable TTL
- **Role-based access**: Define multiple roles with different TTL configurations
- **Secure credential storage**: OCI API credentials stored securely in Vault
- **Automatic revocation**: Tokens can be revoked through Vault's lease management
- **Multi-region support**: Works with any OCI region

## Prerequisites

- Go 1.21 or later
- HashiCorp Vault 1.12+ (dev mode or server mode)
- OCI account with API key authentication configured

## Installation

### Build the Plugin

```bash
# Clone the repository
git clone https://github.com/gordon/Hashicorp-OCI-credential-engine.git
cd Hashicorp-OCI-credential-engine

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

### OCI API Credentials

Before using the plugin, you need to configure it with your OCI API credentials:

```bash
vault write oci/config \
    tenancy_ocid="ocid1.tenancy.oc1..xxxxx" \
    user_ocid="ocid1.user.oc1..xxxxx" \
    fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99" \
    region="us-ashburn-1" \
    private_key=@/path/to/oci_api_key.pem
```

**Parameters:**
- `tenancy_ocid`: The OCID of your OCI tenancy
- `user_ocid`: The OCID of the user for authentication
- `fingerprint`: The fingerprint of the API key
- `region`: The OCI region (e.g., `us-ashburn-1`, `eu-frankfurt-1`)
- `private_key`: The private key content (PEM format) - use `@` to read from file
- `private_key_path`: Alternative to `private_key` - path to the private key file
- `passphrase`: Optional passphrase if the private key is encrypted

### Roles

Create roles to define token configurations:

```bash
# Create a development role with 1-hour default TTL
vault write oci/roles/dev \
    description="Development environment access" \
    default_ttl=3600 \
    max_ttl=14400

# Create a production role with shorter TTL
vault write oci/roles/prod \
    description="Production environment access" \
    default_ttl=1800 \
    max_ttl=3600
```

## Usage

### Generate a Session Token

```bash
vault read oci/creds/dev
```

**Response:**
```json
{
  "data": {
    "session_token": "eyJ...",
    "access_token": "Atbv...",
    "region": "us-ashburn-1",
    "tenancy_ocid": "ocid1.tenancy.oc1..xxxxx",
    "user_ocid": "ocid1.user.oc1..xxxxx"
  },
  "lease_id": "oci/creds/dev/...",
  "lease_duration": 3600,
  "renewable": true
}
```

### Using the Token with OCI CLI

```bash
# Get the session token and configure OCI CLI
export OCI_CLI_AUTH=security_token
export OCI_CLI_SECURITY_TOKEN=$(vault read -field=session_token oci/creds/dev)
export OCI_CLI_REGION=$(vault read -field=region oci/creds/dev)

# Now use OCI CLI without explicit authentication
oci iam user list
```

### Using with OCI Go SDK

```go
import (
    "github.com/oracle/oci-go-sdk/v65/common"
    "github.com/oracle/oci-go-sdk/v65/identity"
)

// Get token from Vault
configProvider := common.NewRawConfigurationProvider(
    tenancyOCID,
    userOCID,
    region,
    fingerprint,
    privateKey,
    &common.Password{Password: passphrase},
)

// Create an identity client
client, err := identity.NewIdentityClientWithConfigurationProvider(configProvider)
if err != nil {
    // handle error
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Vault Server                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            OCI Secrets Engine Plugin                  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │  │
│  │  │ Backend  │  │  Config  │  │   Credentials Path   │ │  │
│  │  │ Factory  │  │   Path   │  │     (creds/*)        │ │  │
│  │  └──────────┘  └──────────┘  └──────────────────────┘ │  │
│  │         │            │                    │           │  │
│  │         └────────────┴────────────────────┘           │  │
│  │                       │                               │  │
│  │              ┌────────▼────────┐                      │  │
│  │              │  OCI Identity   │                      │  │
│  │              │     Client      │                      │  │
│  │              └────────┬────────┘                      │  │
│  └───────────────────────┼───────────────────────────────┘  │
│                          │                                  │
│                          │ HTTPS                            │
└──────────────────────────┼──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  OCI APIs   │
                    │  (Identity) │
                    └─────────────┘
```

## API Reference

### Config Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/config` | Read current configuration |
| `POST/PUT` | `/oci/config` | Create or update configuration |
| `DELETE` | `/oci/config` | Delete configuration |

### Roles Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/roles/:name` | Read a role |
| `POST/PUT` | `/oci/roles/:name` | Create or update a role |
| `DELETE` | `/oci/roles/:name` | Delete a role |

### Credentials Path

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oci/creds/:name` | Generate credentials for a role |

## Development

### Project Structure

```
.
├── backend.go          # Main backend implementation
├── path_config.go      # Configuration management
├── path_creds.go       # Credential generation
├── main.go             # Plugin entry point
├── go.mod              # Go module definition
├── Makefile            # Build automation
└── README.md           # This file
```

### Running Tests

```bash
make test
```

### Local Development with Vault

1. Start Vault in dev mode with plugin directory:
```bash
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin
```

2. In another terminal, register and enable the plugin:
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

vault write sys/plugins/catalog/secrets/oci \
    sha_256="$(sha256sum bin/vault-plugin-secrets-oci | cut -d' ' -f1)" \
    command="vault-plugin-secrets-oci"

vault secrets enable -path=oci oci
```

## TODO / Future Enhancements

- [ ] Complete OCI SDK integration for actual token generation
- [ ] Add support for instance principals authentication
- [ ] Implement token revocation via OCI API
- [ ] Add support for bulk token generation
- [ ] Implement credential rotation workflows
- [ ] Add metrics and telemetry
- [ ] Support for cross-region token generation
- [ ] Integration tests with OCI sandbox environment

## Security Considerations

1. **Private Key Handling**: Private keys are stored encrypted in Vault's storage backend
2. **Token TTL**: Use short TTLs (1-4 hours) for production environments
3. **Audit Logging**: All credential operations are logged to Vault's audit log
4. **Least Privilege**: Create OCI users with minimal required permissions for token generation

## License

MIT License - See LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For issues and questions, please open a GitHub issue or contact the maintainers.

## Related Resources

- [HashiCorp Vault Plugin Documentation](https://developer.hashicorp.com/vault/docs/plugins)
- [OCI Identity Service Documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/overview.htm)
- [OCI Go SDK](https://github.com/oracle/oci-go-sdk)
- [Vault Secrets Engine Tutorial](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine)
