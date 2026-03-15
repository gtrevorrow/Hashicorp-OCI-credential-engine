#!/bin/bash
# Calculate SHA256 and register the OCI plugin with Vault

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_BIN="$REPO_ROOT/bin/vault-plugin-secrets-oci"

# Check if VAULT_ADDR is set, default to dev server if not
export VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
export VAULT_TOKEN=${VAULT_TOKEN:-"root"}

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

vault write sys/plugins/catalog/secret/oci \
    sha_256="$SHA256" \
    command="vault-plugin-secrets-oci"

if [ $? -eq 0 ]; then
    echo "Plugin registered successfully."
    echo ""
    echo "You can now enable it with:"
    echo "vault secrets enable -path=oci -plugin-name=oci plugin"
else
    echo "Failed to register plugin. Ensure Vault is running and VAULT_ADDR is accessible."
    exit 1
fi
