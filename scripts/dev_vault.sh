#!/bin/bash
# Start or stop the local Vault dev server

ACTION=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure a dedicated plugin directory exists with only the correct binary
# to prevent Vault from crashing when trying to load plugins built for other OS/architectures
PLUGIN_DIR="/tmp/vault-dev-plugins"
rm -rf "$PLUGIN_DIR" && mkdir -p "$PLUGIN_DIR"
cp "$REPO_ROOT/bin/vault-plugin-secrets-oci" "$PLUGIN_DIR/"

if [ "$ACTION" == "start" ]; then
    echo "Starting Vault in dev mode..."
    
    # Start vault in the background with nohup to detach it from the shell
    nohup vault server -dev -dev-root-token-id=root -dev-plugin-dir="$PLUGIN_DIR" > /tmp/vault.log 2>&1 </dev/null &
    
    # Save the PID
    echo $! > /tmp/vault.pid
    echo "Vault started with PID $(cat /tmp/vault.pid)."
    echo "Logs are available at /tmp/vault.log"
    echo ""
    echo "Run the following commands in your terminal to set up your environment:"
    echo "export VAULT_ADDR='http://127.0.0.1:8200'"
    echo "export VAULT_TOKEN='root'"
    
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
