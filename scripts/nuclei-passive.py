#!/usr/bin/env python3
"""
nuclei-passive.py — a safety wrapper that lets you use nuclei WITHOUT ever sending
a single request to the target program's infrastructure.

Most bug-bounty programs prohibit automated scanning. This wrapper makes nuclei
*structurally incapable* of touching a remote target: it refuses to invoke nuclei
unless EVERY target is either

  - a loopback address (127.0.0.0/8, localhost, ::1), or
  - an existing local filesystem path (nuclei -file content scanning),

and exits without running anything otherwise. The guarantee comes from the guard,
not from trusting any nuclei flag.

Two rules-safe workflows it enables:

  1. OFFLINE content scan of already-captured artifacts (zero network at all):
       # JS bundles / responses you already saved while manually browsing in Burp
       nuclei-passive.py -file -t exposures/ -target ./loot/js/

  2. LOCALHOST replay / self-hosted lab (zero requests to THEM):
       # you serve captured responses or self-host the target's OSS on 127.0.0.1
       python3 -m http.server 9000 --bind 127.0.0.1 --directory ./loot/responses &
       nuclei-passive.py -u http://127.0.0.1:9000/ -t exposures/

The operator supplies data they already collected during normal manual testing;
this tool sends 0 requests to the target. The program's servers are never touched.

Usage:
    nuclei-passive.py [any nuclei args...]
    nuclei-passive.py --dry-run [args...]    # validate + print cmd, never execute

Exit codes:
    0 — safe; nuclei ran (or was printed in --dry-run / when nuclei is absent)
    2 — REFUSED: a non-local target was requested; nuclei was NOT run
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import sys
from urllib.parse import urlparse

# Flags whose value is a target (single value or comma-separated)
TARGET_VALUE_FLAGS = {"-u", "-target", "-targets"}
# Flags whose value is a FILE containing a list of targets (one per line)
TARGET_LIST_FLAGS = {"-l", "-list"}


def is_loopback_host(host: str | None) -> bool:
    """True only for localhost or a literal loopback IP (127.0.0.0/8, ::1).
    Strict IP parsing — rejects rebinding tricks like '127.0.0.1.evil.com' and
    '127.0.0.1@evil.com' that merely START with a loopback string."""
    if not host:
        return False
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_local_target(tok: str) -> tuple[bool, str]:
    """Return (ok, reason). Local = loopback URL or an existing local path."""
    tok = tok.strip()
    if not tok:
        return True, "empty"
    if "://" in tok:
        host = urlparse(tok).hostname
        if is_loopback_host(host):
            return True, f"loopback url ({host})"
        return False, f"REMOTE url host: {host!r}"
    # no scheme → treat as a filesystem path (nuclei -file mode) or a bare host
    if os.path.exists(tok):
        return True, "local path"
    # a bare hostname/IP with no scheme and no matching local file is treated as a
    # remote target by nuclei → refuse unless it is clearly loopback
    if is_loopback_host(tok.split(":")[0]):
        return True, "loopback host"
    return False, f"not a local path and not loopback: {tok!r}"


def collect_targets(argv: list[str]) -> list[str]:
    """Pull every target token out of the nuclei argv."""
    targets: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in TARGET_VALUE_FLAGS and i + 1 < len(argv):
            targets += [t for t in argv[i + 1].split(",") if t.strip()]
            i += 2
            continue
        if a in TARGET_LIST_FLAGS and i + 1 < len(argv):
            listfile = argv[i + 1]
            if os.path.isfile(listfile):
                with open(listfile, encoding="utf-8", errors="replace") as fh:
                    targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
            else:
                # a -l pointing at a missing file is itself suspicious; record it raw
                targets.append(listfile)
            i += 2
            continue
        i += 1
    return targets


def main(argv: list[str]) -> int:
    dry_run = False
    if argv and argv[0] == "--dry-run":
        dry_run = True
        argv = argv[1:]

    if not argv:
        print("nuclei-passive: no arguments. See --help in the file header.", file=sys.stderr)
        return 2

    targets = collect_targets(argv)
    if not targets:
        print("REFUSED: no -u/-target/-l target found. This wrapper requires an "
              "explicit local target (loopback URL or local path); it will not run "
              "nuclei with an implicit/remote target.", file=sys.stderr)
        return 2

    violations = []
    for t in targets:
        ok, reason = is_local_target(t)
        verdict = "ok" if ok else "REFUSED"
        print(f"  [{verdict}] {t}  ({reason})", file=sys.stderr)
        if not ok:
            violations.append(t)

    if violations:
        print(f"\nREFUSED: {len(violations)} non-local target(s). nuclei was NOT run. "
              f"This tool only scans loopback (127.x / localhost / ::1) or local files — "
              f"the target program's infrastructure is never touched.", file=sys.stderr)
        return 2

    # Belt-and-suspenders: keep a rate cap even though everything is local.
    cmd = ["nuclei"] + argv
    if "-rl" not in argv and "-rate-limit" not in argv:
        cmd += ["-rl", "5"]

    print(f"\n[passive] all {len(targets)} target(s) are local — 0 requests to any "
          f"remote host.\n[passive] cmd: {' '.join(cmd)}", file=sys.stderr)

    if dry_run:
        return 0
    if not shutil.which("nuclei"):
        print("[passive] nuclei not installed — command validated but not executed. "
              "Install nuclei, then re-run.", file=sys.stderr)
        return 0
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
