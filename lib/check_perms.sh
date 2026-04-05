#!/bin/bash
# check_perms.sh — audit known secret directories for permission issues
# Outputs: permission,type,path (tab-separated)
# Never reads file contents

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIRS_FILE="$SCRIPT_DIR/../patterns/directories.txt"

while IFS= read -r dir || [[ -n "$dir" ]]; do
    [[ "$dir" =~ ^#.*$ || -z "$dir" ]] && continue

    # Expand ~ manually
    expanded="${dir/#\~/$HOME}"

    [ -e "$expanded" ] || continue

    perms="$(stat -f '%Sp' "$expanded" 2>/dev/null)"
    type="$([ -d "$expanded" ] && echo "dir" || echo "file")"

    # Flag if group or other has any access
    issue=0
    oct="$(stat -f '%OLp' "$expanded" 2>/dev/null)"
    group_bits=$(( (10#$oct / 10) % 10 ))
    other_bits=$(( 10#$oct % 10 ))

    if [ "$group_bits" -gt 0 ] || [ "$other_bits" -gt 0 ]; then
        issue=1
    fi

    printf '%s\t%s\t%s\t%s\n' "$perms" "$type" "$( [ $issue -eq 1 ] && echo "OPEN" || echo "ok" )" "$expanded"

done < "$DIRS_FILE"
