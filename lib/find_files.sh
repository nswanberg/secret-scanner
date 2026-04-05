#!/bin/bash
# find_files.sh — locate files matching secret filename patterns
# Outputs: permission,modified_date,size,category,risk_flags,path (tab-separated)
# Never reads file contents

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERNS="$SCRIPT_DIR/../patterns/filenames.txt"
SYNC_DIRS=("$HOME/Dropbox" "$HOME/Library/Mobile Documents" "$HOME/Library/CloudStorage")

categorize() {
    local name="$1"
    case "$name" in
        id_rsa*|id_dsa*|id_ecdsa*|id_ed25519*|*_rsa|*_dsa|*_ecdsa|*_ed25519|*.pem|*.p12|*.pfx|*.pkcs12|*.jks|*.keystore)
            echo "ssh/key" ;;
        *.cer|*.crt|*.der)
            echo "certificate" ;;
        credentials*|client_secret*|service_account*|application_default*|access_tokens*|credentials.db)
            echo "cloud-credential" ;;
        .env|.env.*|*.secret|*.secrets|secrets.yml|secrets.yaml|secrets.json)
            echo "env/secrets-file" ;;
        *.token|*_token|*tokens*)
            echo "token" ;;
        .pgpass|.my.cnf|.mylogin.cnf)
            echo "database-credential" ;;
        .netrc|.htpasswd)
            echo "network-credential" ;;
        kubeconfig|*.kubeconfig)
            echo "kubernetes" ;;
        *)
            echo "generic-secret" ;;
    esac
}

risk_flags() {
    local path="$1"
    local perms="$2"
    local flags=()

    # World-readable
    if [[ "$perms" =~ .......r.. ]] || [[ "$perms" =~ ........r. ]] || [[ "$perms" =~ .........r ]]; then
        flags+=("world-readable")
    fi

    # Group-readable
    if [[ "$perms" =~ ....r..... ]]; then
        flags+=("group-readable")
    fi

    # In a sync folder
    for sync_dir in "${SYNC_DIRS[@]}"; do
        if [[ "$path" == "$sync_dir"* ]]; then
            flags+=("in-sync-folder")
            break
        fi
    done

    # Inside a git repo
    local dir
    dir="$(dirname "$path")"
    if git -C "$dir" rev-parse --git-dir &>/dev/null 2>&1; then
        flags+=("in-git-repo")
    fi

    if [ ${#flags[@]} -eq 0 ]; then
        echo "none"
    else
        echo "$(IFS=','; echo "${flags[*]}")"
    fi
}

# Build find args from patterns file
find_args=()
first=1
while IFS= read -r pattern || [[ -n "$pattern" ]]; do
    [[ "$pattern" =~ ^#.*$ || -z "$pattern" ]] && continue
    if [ $first -eq 1 ]; then
        find_args+=(-name "$pattern")
        first=0
    else
        find_args+=(-o -name "$pattern")
    fi
done < "$PATTERNS"

# Dirs to skip: package manager caches and third-party code contain
# test certs, example keys, etc. that are not real secrets.
EXCLUDE_PATHS=(
    "*/.Trash/*"
    "*/node_modules/*"
    "*/.git/*"
    # Package manager caches
    "*/.cache/*"
    "*/.cargo/registry/*"
    "*/.bun/install/cache/*"
    "*/.npm/*"
    "*/.yarn/*"
    "*/.m2/repository/*"
    "*/go/pkg/mod/*"
    # Toolchain internals
    "*/google-cloud-sdk/platform/*"
    "*/google-cloud-sdk/lib/*"
    "*/.pyenv/*"
    "*/.rustup/*"
    "*/.nvm/*"
    # IDE/editor extensions
    "*/.cursor/extensions/*"
    "*/.vscode/extensions/*"
    "*/.codex/*"
    # Python venvs inside projects
    "*/.venv/*"
    "*/venv/*"
)

EXCLUDE_ARGS=()
for p in "${EXCLUDE_PATHS[@]}"; do
    EXCLUDE_ARGS+=(-not -path "$p")
done

# Run find across home dir
find "$HOME" \
    "${EXCLUDE_ARGS[@]}" \
    \( "${find_args[@]}" \) \
    -type f 2>/dev/null | while read -r filepath; do

    name="$(basename "$filepath")"
    perms="$(stat -f '%Sp' "$filepath" 2>/dev/null)"
    mdate="$(stat -f '%Sm' -t '%Y-%m-%d' "$filepath" 2>/dev/null)"
    size="$(stat -f '%z' "$filepath" 2>/dev/null)"
    category="$(categorize "$name")"
    flags="$(risk_flags "$filepath" "$perms")"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$perms" "$mdate" "$size" "$category" "$flags" "$filepath"
done
