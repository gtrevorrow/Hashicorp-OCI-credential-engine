#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

USERNAME="${SMOKE_USERNAME:-alice}"
PASSWORD="${SMOKE_PASSWORD:-pass123}"
GROUP_NAME="${SMOKE_GROUP_NAME:-dev-team}"
ROLE_NAME="${SMOKE_ROLE_NAME:-developer}"
REQUESTED_TOKEN_TYPE="${SMOKE_REQUESTED_TOKEN_TYPE:-urn:oci:token-type:oci-rpst}"
RES_TYPE="${SMOKE_RES_TYPE:-ref_vault}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

require_command vault
require_command jq

echo "Checking Vault dev server..."
vault status >/dev/null

echo "Checking OCI mount..."
vault path-help oci/ >/dev/null

echo "Ensuring userpass auth method is enabled..."
if ! vault auth list -format=json | jq -e 'has("userpass/")' >/dev/null; then
    vault auth enable userpass >/dev/null
fi

echo "Writing policy oci-smoke-self-mint..."
vault policy write oci-smoke-self-mint - <<EOF >/dev/null
path "oci/exchange/${ROLE_NAME}" {
  capabilities = ["create", "update"]
}
EOF

echo "Creating internal identity group ${GROUP_NAME}..."
vault write identity/group name="${GROUP_NAME}" type="internal" >/dev/null
GROUP_ID="$(vault read -format=json "identity/group/name/${GROUP_NAME}" | jq -r '.data.id')"

echo "Creating userpass user ${USERNAME}..."
vault write "auth/userpass/users/${USERNAME}" \
  password="${PASSWORD}" \
  token_policies="oci-smoke-self-mint" >/dev/null

echo "Writing role ${ROLE_NAME}..."
vault write "oci/role/${ROLE_NAME}" \
  default_ttl=3600 \
  max_ttl=7200 \
  self_mint_custom_claims='{
    "entity_ref":"{{ vault.entity.id }}",
    "entity_name":"{{ vault.entity.name }}",
    "display_name":"{{ vault.request.display_name }}",
    "mount_type":"{{ vault.request.mount_type }}",
    "group_list":"{{ join(vault.groups, \",\") }}"
  }' >/dev/null

echo "Logging in as ${USERNAME} to create the entity/alias..."
ALICE_TOKEN="$(env -u VAULT_TOKEN vault login -method=userpass -format=json username="${USERNAME}" password="${PASSWORD}" | jq -r '.auth.client_token')"
ENTITY_ID="$(VAULT_TOKEN="${ALICE_TOKEN}" vault token lookup -format=json | jq -r '.data.entity_id')"

if [[ -z "${ENTITY_ID}" || "${ENTITY_ID}" == "null" ]]; then
    echo "Failed to determine entity_id for ${USERNAME}" >&2
    exit 1
fi

echo "Attaching entity ${ENTITY_ID} to group ${GROUP_NAME}..."
vault write "identity/group/id/${GROUP_ID}" \
  name="${GROUP_NAME}" \
  type="internal" \
  member_entity_ids="${ENTITY_ID}" >/dev/null

echo "Logging in again as ${USERNAME} so the token carries current entity/group context..."
ALICE_TOKEN="$(env -u VAULT_TOKEN vault login -method=userpass -format=json username="${USERNAME}" password="${PASSWORD}" | jq -r '.auth.client_token')"

echo "Running self-mint exchange as non-root user ${USERNAME}..."
RESPONSE_JSON="$(VAULT_TOKEN="${ALICE_TOKEN}" vault write -format=json "oci/exchange/${ROLE_NAME}" \
  requested_token_type="${REQUESTED_TOKEN_TYPE}" \
  res_type="${RES_TYPE}")"

echo
echo "Resolved self-minted subject token claims:"
echo "${RESPONSE_JSON}" | jq '.data.resolved_subject_token_claims'

echo
echo "OCI session token received:"
echo "${RESPONSE_JSON}" | jq -r '
  .data
  | if (.rpst_token // "") != "" then .rpst_token
    elif (.session_token // "") != "" then .session_token
    elif (.access_token // "") != "" then .access_token
    else "missing token field"
    end
'

echo
echo "Expected highlights:"
echo "- entity_ref is non-empty"
echo "- entity_name is non-empty when Vault identity has a name for the entity"
echo "- display_name matches the userpass login display name"
echo "- mount_type should be oci because it comes from vault.request.mount_type on the exchange request"
echo "- vault_alias_mount_type should be userpass because the caller authenticated through userpass"
echo "- group_list should include ${GROUP_NAME}"
echo
echo "Smoke test completed."
