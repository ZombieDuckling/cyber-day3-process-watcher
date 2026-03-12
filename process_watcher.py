#!/usr/bin/env python3
"""
Suspicious process watcher (beginner-friendly).

This script reads the local process list and applies simple flags:
1) keyword matches in command names/arguments
2) high CPU usage
3) suspicious execution paths (/tmp, /var/tmp)

It is an educational triage tool, not malware detection software.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List

# Simple keyword rules for initial triage.
SUSPICIOUS_KEYWORDS = [
    "mimikatz",
    "metasploit",
    "msfconsole",
    "netcat",
    "ncat",
    "nc -e",
    "powershell -enc",
    "base64 -d",
    "xmrig",
    "cryptominer",
    "reverse shell",
]

SUSPICIOUS_PATHS = ["/tmp/", "/var/tmp/"]


def run_ps() -> List[Dict[str, str]]:
    """Return process rows using `ps` for broad compatibility on macOS/Linux."""
    cmd = ["ps", "-axo", "pid=,ppid=,%cpu=,%mem=,comm=,args="]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    rows: List[Dict[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Split first 5 columns, then keep the rest as args.
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue

        pid, ppid, cpu, mem, comm, args = parts
        rows.append(
            {
                "pid": pid,
                "ppid": ppid,
                "cpu": cpu,
                "mem": mem,
                "comm": comm,
                "args": args,
            }
        )

    return rows


def flag_reasons(proc: Dict[str, str], cpu_threshold: float) -> List[str]:
    """Return a list of simple reasons a process might be suspicious."""
    reasons: List[str] = []
    haystack = f"{proc['comm']} {proc['args']}".lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in haystack:
            reasons.append(f"keyword:{keyword}")

    for path in SUSPICIOUS_PATHS:
        if path in haystack:
            reasons.append(f"path:{path}")

    try:
        cpu = float(proc["cpu"])
        if cpu >= cpu_threshold:
            reasons.append(f"high_cpu:{cpu}%")
    except ValueError:
        pass

    return reasons


def scan(cpu_threshold: float, max_items: int) -> List[Dict[str, str]]:
    """Scan processes and return flagged entries."""
    findings = []
    for proc in run_ps():
        reasons = flag_reasons(proc, cpu_threshold)
        if reasons:
            findings.append({**proc, "reasons": ", ".join(reasons)})

    findings.sort(key=lambda row: float(row["cpu"]), reverse=True)
    return findings[:max_items]


def print_findings(findings: List[Dict[str, str]]) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{now}] Flagged processes: {len(findings)}")
    if not findings:
        print("No suspicious flags found with current rules.")
        return

    print("-" * 100)
    print(f"{'PID':<8} {'CPU%':<8} {'MEM%':<8} {'COMMAND':<24} REASONS")
    print("-" * 100)
    for row in findings:
        print(
            f"{row['pid']:<8} {row['cpu']:<8} {row['mem']:<8} "
            f"{row['comm'][:24]:<24} {row['reasons']}"
        )
    print("-" * 100)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Beginner-friendly suspicious process watcher"
    )
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        default=70.0,
        help="Flag processes with CPU >= threshold (default: 70)",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=25,
        help="Maximum number of flagged rows to print (default: 25)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously with interval seconds",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Seconds between scans in watch mode (default: 10)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.watch:
        try:
            while True:
                findings = scan(args.cpu_threshold, args.max_items)
                print_findings(findings)
                time.sleep(max(args.interval, 1))
        except KeyboardInterrupt:
            print("\nStopped by user.")
            return 0
    else:
        findings = scan(args.cpu_threshold, args.max_items)
        print_findings(findings)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as err:
        print(f"Failed to run process scan: {err}", file=sys.stderr)
        raise SystemExit(1)
