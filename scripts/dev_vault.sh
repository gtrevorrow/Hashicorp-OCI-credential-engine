#!/bin/bash
# Start or stop the local Vault dev server

ACTION=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEV_ENV_FILE="$REPO_ROOT/.env.local"
DEV_SELF_MINT_KEY_FILE="$REPO_ROOT/.vault-dev-self-mint-key.pem"

reset_dev_oci_env() {
    unset OCI_DOMAIN_URL
    unset OCI_CLIENT_ID
    unset OCI_CLIENT_SECRET
    unset OCI_DEFAULT_TTL
    unset OCI_MAX_TTL
    unset OCI_ENABLE_PLUGIN_ISSUED_SUBJECT_TOKEN
    unset OCI_STRICT_ROLE_NAME_MATCH
    unset OCI_SUBJECT_TOKEN_ROLE_MAPPINGS
    unset OCI_SUBJECT_TOKEN_ALLOWED_AUDIENCES
    unset OCI_SUBJECT_TOKEN_SELF_MINT_ENABLED
    unset OCI_SUBJECT_TOKEN_SELF_MINT_ISSUER
    unset OCI_SUBJECT_TOKEN_SELF_MINT_AUDIENCE
    unset OCI_SUBJECT_TOKEN_SELF_MINT_TTL_SECONDS
    unset OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY
    unset OCI_DEBUG_RETURN_RESOLVED_SUBJECT_TOKEN_CLAIMS
}

if [ "$ACTION" == "start" ]; then
    echo "Starting Vault in dev mode..."

    echo "Building plugin..."
    if ! make -C "$REPO_ROOT" build; then
        echo "Plugin build failed."
        exit 1
    fi

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

    reset_dev_oci_env
    if [ -f "$DEV_ENV_FILE" ]; then
        echo "Loading local dev settings from $DEV_ENV_FILE..."
        # shellcheck disable=SC1090
        . "$DEV_ENV_FILE"
    fi

    if [ "${OCI_SUBJECT_TOKEN_SELF_MINT_ENABLED:-}" = "true" ] && [ -z "${OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY:-}" ]; then
        if [ -f "$DEV_SELF_MINT_KEY_FILE" ]; then
            echo "Reusing local dev self-mint signing key from $DEV_SELF_MINT_KEY_FILE..."
        else
            echo "Generating local dev self-mint signing key at $DEV_SELF_MINT_KEY_FILE..."
            if ! openssl genrsa -out "$DEV_SELF_MINT_KEY_FILE" 2048 >/dev/null 2>&1; then
                echo "Failed to generate local dev self-mint signing key with openssl."
                exit 1
            fi
            chmod 600 "$DEV_SELF_MINT_KEY_FILE"
        fi
        OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY="$(cat "$DEV_SELF_MINT_KEY_FILE")"
    fi

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

    if [ -n "${OCI_DOMAIN_URL:-}" ] && [ -n "${OCI_CLIENT_ID:-}" ] && [ -n "${OCI_CLIENT_SECRET:-}" ]; then
        echo "Seeding OCI backend config from local dev settings..."
        CONFIG_ARGS=(
            "domain_url=$OCI_DOMAIN_URL"
            "client_id=$OCI_CLIENT_ID"
            "client_secret=$OCI_CLIENT_SECRET"
        )

        if [ -n "${OCI_DEFAULT_TTL:-}" ]; then
            CONFIG_ARGS+=("default_ttl=$OCI_DEFAULT_TTL")
        fi
        if [ -n "${OCI_MAX_TTL:-}" ]; then
            CONFIG_ARGS+=("max_ttl=$OCI_MAX_TTL")
        fi
        if [ -n "${OCI_ENABLE_PLUGIN_ISSUED_SUBJECT_TOKEN:-}" ]; then
            CONFIG_ARGS+=("enable_plugin_issued_subject_token=$OCI_ENABLE_PLUGIN_ISSUED_SUBJECT_TOKEN")
        fi
        if [ -n "${OCI_STRICT_ROLE_NAME_MATCH:-}" ]; then
            CONFIG_ARGS+=("strict_role_name_match=$OCI_STRICT_ROLE_NAME_MATCH")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_ROLE_MAPPINGS:-}" ]; then
            CONFIG_ARGS+=("subject_token_role_mappings=$OCI_SUBJECT_TOKEN_ROLE_MAPPINGS")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_ALLOWED_AUDIENCES:-}" ]; then
            CONFIG_ARGS+=("subject_token_allowed_audiences=$OCI_SUBJECT_TOKEN_ALLOWED_AUDIENCES")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_SELF_MINT_ENABLED:-}" ]; then
            CONFIG_ARGS+=("subject_token_self_mint_enabled=$OCI_SUBJECT_TOKEN_SELF_MINT_ENABLED")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_SELF_MINT_ISSUER:-}" ]; then
            CONFIG_ARGS+=("subject_token_self_mint_issuer=$OCI_SUBJECT_TOKEN_SELF_MINT_ISSUER")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_SELF_MINT_AUDIENCE:-}" ]; then
            CONFIG_ARGS+=("subject_token_self_mint_audience=$OCI_SUBJECT_TOKEN_SELF_MINT_AUDIENCE")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_SELF_MINT_TTL_SECONDS:-}" ]; then
            CONFIG_ARGS+=("subject_token_self_mint_ttl_seconds=$OCI_SUBJECT_TOKEN_SELF_MINT_TTL_SECONDS")
        fi
        if [ -n "${OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY:-}" ]; then
            CONFIG_ARGS+=("subject_token_self_mint_private_key=$OCI_SUBJECT_TOKEN_SELF_MINT_PRIVATE_KEY")
        fi
        if [ -n "${OCI_DEBUG_RETURN_RESOLVED_SUBJECT_TOKEN_CLAIMS:-}" ]; then
            CONFIG_ARGS+=("debug_return_resolved_subject_token_claims=$OCI_DEBUG_RETURN_RESOLVED_SUBJECT_TOKEN_CLAIMS")
        fi

        vault write oci/config "${CONFIG_ARGS[@]}"
    else
        echo "OCI backend config not seeded. Set OCI_DOMAIN_URL, OCI_CLIENT_ID, and OCI_CLIENT_SECRET in $DEV_ENV_FILE to auto-configure it on startup."
    fi

    echo ""
    echo "Dev Vault is ready."
    echo "Environment:"
    echo "export VAULT_ADDR='$VAULT_ADDR'"
    echo "export VAULT_TOKEN='$VAULT_TOKEN'"
    if [ -f "$DEV_SELF_MINT_KEY_FILE" ]; then
        echo "Self-mint signing key: $DEV_SELF_MINT_KEY_FILE"
    fi

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
