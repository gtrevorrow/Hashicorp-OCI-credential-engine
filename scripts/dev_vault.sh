#!/bin/bash
# Keep credentials out of shell tracing, including when invoked with bash -x.
set +x
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/dev_vault.py" "${1:-}"
