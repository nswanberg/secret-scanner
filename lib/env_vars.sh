#!/bin/bash
# env_vars.sh — report env var NAMES that match secret patterns
# Never outputs values

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERNS="$SCRIPT_DIR/../patterns/env_patterns.txt"

while IFS='=' read -r name _; do
    [ -z "$name" ] && continue
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        [[ "$pattern" =~ ^#.*$ || -z "$pattern" ]] && continue
        if echo "$name" | grep -qi "$pattern"; then
            echo "$name"
            break
        fi
    done < "$PATTERNS"
done < <(env)
