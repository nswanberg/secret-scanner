#!/usr/bin/env python3
"""
report.py — collate output from all scanner modules and write a log file.
Run via scan.sh, not directly.
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path


LOG_DIR = Path.home() / ".secret-scanner"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"


def section(f, title):
    f.write(f"\n{'='*60}\n{title}\n{'='*60}\n")


def write_report(data: dict):
    with open(LOG_FILE, "w") as f:
        f.write(f"secret-scanner report\n")
        f.write(f"generated: {datetime.now().isoformat()}\n")
        f.write(f"host:      {os.uname().nodename}\n")
        f.write(f"user:      {os.environ.get('USER', '')}\n")

        # --- Secret files ---
        section(f, "SECRET FILES")
        files = data.get("files", [])
        if not files:
            f.write("  none found\n")
        else:
            # Group by category
            by_cat = {}
            for entry in files:
                cat = entry.get("category", "unknown")
                by_cat.setdefault(cat, []).append(entry)

            for cat, items in sorted(by_cat.items()):
                f.write(f"\n  [{cat}]\n")
                for item in sorted(items, key=lambda x: x.get("path", "")):
                    flags = item.get("flags", "none")
                    flag_str = f"  !! {flags}" if flags != "none" else ""
                    f.write(
                        f"    {item['perms']}  {item['mdate']}  "
                        f"{int(item['size']):>8,}B  {item['path']}{flag_str}\n"
                    )

        # --- Directory permissions ---
        section(f, "KNOWN SECRET DIRECTORIES — PERMISSION AUDIT")
        dirs = data.get("dirs", [])
        if not dirs:
            f.write("  none found\n")
        else:
            issues = [d for d in dirs if d.get("status") == "OPEN"]
            ok = [d for d in dirs if d.get("status") != "OPEN"]

            if issues:
                f.write("\n  PERMISSION ISSUES:\n")
                for d in issues:
                    f.write(f"    {d['perms']}  {d['type']}  {d['path']}\n")
            f.write(f"\n  OK ({len(ok)} entries with tight permissions)\n")
            for d in ok:
                f.write(f"    {d['perms']}  {d['type']}  {d['path']}\n")

        # --- Env vars ---
        section(f, "ENVIRONMENT VARIABLES WITH SECRET-LIKE NAMES")
        env_vars = data.get("env_vars", [])
        if not env_vars:
            f.write("  none found\n")
        else:
            for name in sorted(env_vars):
                f.write(f"  {name}\n")

        # --- Keychain ---
        section(f, "KEYCHAIN ENTRIES (service + account names only)")
        keychain = data.get("keychain", [])
        if not keychain:
            f.write("  none found\n")
        else:
            for entry in sorted(keychain, key=lambda x: x.get("service", "")):
                f.write(
                    f"  {entry.get('service',''):<50}  "
                    f"{entry.get('account',''):<30}  "
                    f"modified: {entry.get('modified','')}\n"
                )

        # --- Summary ---
        section(f, "SUMMARY")
        risky = [e for e in files if e.get("flags", "none") != "none"]
        perm_issues = [d for d in dirs if d.get("status") == "OPEN"]
        f.write(f"  secret files found:          {len(files)}\n")
        f.write(f"  files with risk flags:       {len(risky)}\n")
        f.write(f"  dir permission issues:       {len(perm_issues)}\n")
        f.write(f"  env vars with secret names:  {len(env_vars)}\n")
        f.write(f"  keychain entries:            {len(keychain)}\n")
        f.write(f"\n  log written to: {LOG_FILE}\n")

    return LOG_FILE


def parse_files(raw: str):
    results = []
    for line in raw.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        results.append({
            "perms": parts[0],
            "mdate": parts[1],
            "size": parts[2],
            "category": parts[3],
            "flags": parts[4],
            "path": parts[5],
        })
    return results


def parse_dirs(raw: str):
    results = []
    for line in raw.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        results.append({
            "perms": parts[0],
            "type": parts[1],
            "status": parts[2],
            "path": parts[3],
        })
    return results


def parse_keychain(raw: str):
    results = []
    for line in raw.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        results.append({
            "service": parts[0],
            "account": parts[1] if len(parts) > 1 else "",
            "created": parts[2] if len(parts) > 2 else "",
            "modified": parts[3] if len(parts) > 3 else "",
        })
    return results


if __name__ == "__main__":
    # Read JSON bundle from stdin: {"files": "...", "dirs": "...", "env_vars": "...", "keychain": "..."}
    raw = sys.stdin.read()
    bundle = json.loads(raw)

    data = {
        "files": parse_files(bundle.get("files", "")),
        "dirs": parse_dirs(bundle.get("dirs", "")),
        "env_vars": [v for v in bundle.get("env_vars", "").strip().splitlines() if v],
        "keychain": parse_keychain(bundle.get("keychain", "")),
    }

    log_path = write_report(data)
    print(f"Report written to: {log_path}")
