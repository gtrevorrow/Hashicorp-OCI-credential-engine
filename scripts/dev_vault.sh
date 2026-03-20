#!/bin/bash
# Start or stop the local Vault dev server

ACTION=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$ACTION" == "start" ]; then
    echo "Starting Vault in dev mode..."

    PLUGIN_BIN="$REPO_ROOT/bin/vault-plugin-secrets-oci"
    PLUGIN_DIR="/tmp/vault-dev-plugins"

    if [ ! -f "$PLUGIN_BIN" ]; then
        echo "Error: Plugin binary not found at $PLUGIN_BIN"
        echo "Please build the plugin first using 'make build'"
        exit 1
    fi

    # Ensure a dedicated plugin directory exists with only the correct binary
    # to prevent Vault from crashing when trying to load plugins built for other OS/architectures
    rm -rf "$PLUGIN_DIR" && mkdir -p "$PLUGIN_DIR"
    cp "$PLUGIN_BIN" "$PLUGIN_DIR/"

    # Start vault in the background with nohup to detach it from the shell
    nohup vault server -dev -dev-root-token-id=root -dev-plugin-dir="$PLUGIN_DIR" > /tmp/vault.log 2>&1 </dev/null &

    # Save the PID
    echo $! > /tmp/vault.pid
    PID=$(cat /tmp/vault.pid)

    export VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
    export VAULT_TOKEN=${VAULT_TOKEN:-"root"}

    echo "Vault started with PID $PID."
    echo "Logs are available at /tmp/vault.log"

    echo "Waiting for Vault to become ready..."
    for _ in $(seq 1 30); do
        if vault status >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    if ! vault status >/dev/null 2>&1; then
        echo "Vault did not become ready in time."
        echo "Last log lines:"
        tail -n 50 /tmp/vault.log 2>/dev/null || true
        exit 1
    fi

    echo "Registering OCI plugin..."
    "$SCRIPT_DIR/register_plugin.sh"

    echo "Enabling OCI secrets engine mount..."
    if vault read sys/mounts/oci/tune >/dev/null 2>&1; then
        echo "OCI secrets engine already mounted."
    else
        vault secrets enable -path=oci -plugin-name=oci plugin
    fi

    echo ""
    echo "Dev Vault is ready."
    echo "Environment:"
    echo "export VAULT_ADDR='$VAULT_ADDR'"
    echo "export VAULT_TOKEN='$VAULT_TOKEN'"

elif [ "$ACTION" == "stop" ]; then
    if [ -f /tmp/vault.pid ]; then
        PID=$(cat /tmp/vault.pid)
        echo "Stopping Vault (PID $PID)..."
        kill $PID 2>/dev/null
        rm /tmp/vault.pid
        echo "Vault stopped."
    else
        echo "Vault PID file not found."
        # Fallback to pkill if process is running
        pkill -f "vault server -dev" && echo "Killed vault process" || echo "No vault process found."
    fi
else
    echo "Usage: $0 {start|stop}"
    exit 1
fi
