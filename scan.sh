#!/bin/bash
# scan.sh — entry point for secret-scanner
# Usage: ./scan.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[secret-scanner] starting scan..."

echo "  scanning files..."
FILES="$(bash "$SCRIPT_DIR/lib/find_files.sh")"

echo "  checking directory permissions..."
DIRS="$(bash "$SCRIPT_DIR/lib/check_perms.sh")"

echo "  scanning environment variables..."
ENV_VARS="$(bash "$SCRIPT_DIR/lib/env_vars.sh")"

echo "  reading keychain metadata..."
KEYCHAIN="$(python3 "$SCRIPT_DIR/lib/keychain.py")"

echo "  generating report..."

python3 "$SCRIPT_DIR/report.py" <<EOF
$(python3 -c "
import json, sys
print(json.dumps({
    'files':    sys.argv[1],
    'dirs':     sys.argv[2],
    'env_vars': sys.argv[3],
    'keychain': sys.argv[4],
}))" "$FILES" "$DIRS" "$ENV_VARS" "$KEYCHAIN")
EOF
