#!/usr/bin/env python3
"""
keychain.py — list keychain entry service names and accounts only.
Never outputs passwords or secret values.
"""

import subprocess
import sys
import re


def dump_keychain_names():
    """
    Run `security dump-keychain` and extract only service/account names.
    Explicitly strips any password or data fields.
    """
    try:
        result = subprocess.run(
            ["security", "dump-keychain"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: keychain dump timed out", file=sys.stderr)
        return []
    except FileNotFoundError:
        print("ERROR: security command not found", file=sys.stderr)
        return []

    entries = []
    current = {}

    for line in result.stdout.splitlines():
        # New entry boundary
        if line.startswith("keychain:") or line.strip().startswith("class:"):
            if current:
                entries.append(current)
            current = {}
            continue

        # Extract service name (svce)
        m = re.search(r'"svce"<blob>="([^"]*)"', line)
        if m:
            current["service"] = m.group(1)
            continue

        # Extract account name (acct)
        m = re.search(r'"acct"<blob>="([^"]*)"', line)
        if m:
            current["account"] = m.group(1)
            continue

        # Extract creation date
        m = re.search(r'"cdat"<timedate>=0x[0-9A-Fa-f]+ "([^"]*)"', line)
        if m:
            current["created"] = m.group(1)
            continue

        # Extract modification date
        m = re.search(r'"mdat"<timedate>=0x[0-9A-Fa-f]+ "([^"]*)"', line)
        if m:
            current["modified"] = m.group(1)
            continue

        # Explicitly skip password/data lines
        if '"data"' in line or '"password"' in line or "<secret>" in line:
            continue

    if current:
        entries.append(current)

    return entries


def main():
    entries = dump_keychain_names()
    seen = set()

    for entry in entries:
        service = entry.get("service", "")
        account = entry.get("account", "")
        created = entry.get("created", "")
        modified = entry.get("modified", "")

        if not service and not account:
            continue

        key = f"{service}|{account}"
        if key in seen:
            continue
        seen.add(key)

        print(f"{service}\t{account}\t{created}\t{modified}")


if __name__ == "__main__":
    main()
