#!/bin/bash
# Calculate SHA256 and register the OCI plugin with Vault
set +x
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_BIN="$REPO_ROOT/bin/vault-plugin-secrets-oci"

# Manual registration requires an explicitly selected target and credential.
: "${VAULT_ADDR:?Set VAULT_ADDR explicitly or load dev_vault.sh env}"
: "${VAULT_TOKEN:?Set VAULT_TOKEN explicitly or load dev_vault.sh env}"
export VAULT_ADDR VAULT_TOKEN

if [ ! -f "$PLUGIN_BIN" ]; then
    echo "Error: Plugin binary not found at $PLUGIN_BIN"
    echo "Please build the plugin first using 'make build'"
    exit 1
fi

echo "Calculating SHA256 for vault-plugin-secrets-oci..."

# Calculate the hash depending on the OS
if command -v sha256sum >/dev/null 2>&1; then
    SHA256=$(sha256sum "$PLUGIN_BIN" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    SHA256=$(shasum -a 256 "$PLUGIN_BIN" | cut -d' ' -f1)
else
    echo "Error: Neither sha256sum nor shasum is available on this system."
    exit 1
fi

echo "SHA256: $SHA256"
echo "Registering plugin with Vault at $VAULT_ADDR..."

if vault write sys/plugins/catalog/secret/oci \
    sha_256="$SHA256" \
    command="vault-plugin-secrets-oci" >/dev/null 2>&1; then
    echo "Plugin registered successfully."
    echo ""
    echo "You can now enable it with:"
    echo "vault secrets enable -path=oci -plugin-name=oci plugin"
else
    echo "Failed to register plugin. Check the selected Vault target and permissions; raw output suppressed."
    exit 1
fi
