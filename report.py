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

MITIGATIONS = """
  [ssh/key]
    Threat:     Plaintext private keys on disk. Exfiltrable by any process
                running as your user. Common target for malicious packages.
    Mitigation: 1Password SSH agent — keys live in 1Password, never on disk.
                Touch ID per-session. 1P serves them via SSH_AUTH_SOCK.
    Also:       Ensure 600 permissions. Remove keys you no longer use.

  [cloud-credential]
    Threat:     Long-lived access keys (AWS, GCP) are the highest-value target.
                A stolen AWS key can spin up resources, access data, etc.
    Mitigation: AWS: use `op plugin` to serve credentials via 1Password, then
                delete ~/.aws/credentials. Or better: migrate to IAM Identity
                Center for short-lived session tokens (no persistent keys).
                GCP: `gcloud auth login` per-session. Delete stored ADC if not
                needed for local dev. Revoke with `gcloud auth revoke`.
    Also:       Scope IAM permissions tightly. Enable CloudTrail/audit logs.
                Set billing alerts. Rotate keys if you can't eliminate them.

  [env/secrets-file]
    Threat:     API keys, database URLs, etc. in plaintext .env files. Easy to
                accidentally commit to git. Readable by any local process.
    Mitigation: Use `op run` with op:// references — secrets are injected as
                env vars at runtime, never written to disk. Keep a .env.example
                with placeholder values for documentation.
    Also:       Ensure .env is in .gitignore. Check git history for past commits
                of secrets (`git log -p -- .env`).

  [cli-auth]
    Threat:     OAuth tokens for tools like gh, codex, npm. Stored on disk with
                600 permissions. Scoped and revocable, but still exfiltrable.
    Mitigation: These tools chose plaintext storage deliberately — if an attacker
                runs as your user, they can call the CLI directly anyway. The
                real defense is: review token scopes (minimize permissions),
                enable 2FA on the backing accounts, monitor for anomalous usage,
                and revoke tokens you no longer need.
    Also:       `gh auth status` to review scopes. `npm token list` to audit.
                Some tools support `op plugin` (gh does) to avoid disk storage.

  [certificate]
    Threat:     Usually low risk — most .cer/.crt/.der files are public certs
                or test fixtures from dependencies. Private key files (.key,
                .pem) paired with certs are the actual concern.
    Mitigation: If found in dependency caches, ignore (test data). If found in
                your own projects, ensure the private key half is protected.

  [database-credential]
    Threat:     .pgpass, .my.cnf contain database passwords in plaintext.
    Mitigation: Move to `op run` or 1Password. For local dev databases with
                no real data, low risk. For production credentials, high risk.
    Also:       Ensure 600 permissions at minimum.

  [network-credential]
    Threat:     .netrc contains login/password pairs for services. Plaintext.
    Mitigation: Delete if the service is no longer used. Move to 1Password
                if still needed. Ensure 600 permissions.

  [kubernetes]
    Threat:     kubeconfig files may contain cluster credentials or tokens.
    Mitigation: Use short-lived tokens via cloud provider auth plugins.
                Don't store cluster admin creds locally.

  [generic-secret]
    Threat:     Matched by filename pattern but may be a false positive (e.g.
                Keynote .key files, application config). Review individually.
    Mitigation: Check if the file actually contains secret material. Delete
                or protect accordingly.

  [general guidance]
    The primary filesystem threat is smash-and-grab: a malicious process reads
    known credential paths and exfiltrates them. Defenses in order of value:
      1. Delete secrets you don't need (zero attack surface)
      2. Use Keychain or 1Password (not on disk at all)
      3. Use short-lived tokens (limited blast radius if stolen)
      4. Use `op run` for project secrets (never touch disk)
      5. File permissions 600/700 (stops other users, not your own)
      6. Monitor and alert (CloudTrail, GitHub audit log, billing alerts)
"""


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

        # --- Mitigations ---
        section(f, "MITIGATION STRATEGIES BY CATEGORY")
        f.write(MITIGATIONS)

        # --- Summary ---
        section(f, "SUMMARY")
        risky = [e for e in files if e.get("flags", "none") != "none"]
        perm_issues = [d for d in dirs if d.get("status") == "OPEN"]

        # Count by category
        by_cat = {}
        for entry in files:
            cat = entry.get("category", "unknown")
            by_cat[cat] = by_cat.get(cat, 0) + 1

        f.write(f"  secret files found:          {len(files)}\n")
        for cat, count in sorted(by_cat.items()):
            f.write(f"    {cat:<30} {count}\n")
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
