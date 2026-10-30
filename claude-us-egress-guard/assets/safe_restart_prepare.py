#!/usr/bin/env python3
"""Stop protected applications before reboot; never performs the reboot."""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from typing import List, Optional


def run(args: List[str], timeout: float = 8.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def count_processes(prefix: str) -> int:
    result = run(["/bin/ps", "-ww", "-axo", "args="], 7)
    return sum(line.startswith(prefix) for line in result.stdout.splitlines())


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def vpn_state(service: str) -> str:
    result = run(["/usr/sbin/scutil", "--nc", "status", service], 5)
    text = (result.stdout + "\n" + result.stderr).strip()
    return next((line.strip() for line in text.splitlines() if line.strip()), "Unknown")


def default_route() -> str:
    result = run(["/sbin/route", "-n", "get", "1.1.1.1"], 5)
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    return match.group(1) if match else ""


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claude-prefix", default="/Applications/Claude.app/Contents/")
    parser.add_argument("--xray-label", default="com.example.claude-us-xray")
    parser.add_argument("--xray-port", type=int, default=17891)
    parser.add_argument("--vpn-service", default="Day8")
    parser.add_argument("--clash-app", default="Clash Verge")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if count_processes(args.claude_prefix) > 0:
        run(["/usr/bin/osascript", "-e", 'tell application "Claude" to quit'], 8)
        for _ in range(20):
            if count_processes(args.claude_prefix) == 0:
                break
            time.sleep(0.5)
        else:
            print("BLOCKED_CLAUDE_STILL_RUNNING", file=sys.stderr)
            return 74

    uid = os.getuid()
    run(
        ["/bin/launchctl", "bootout", "gui/{}/{}".format(uid, args.xray_label)],
        8,
    )
    run(["/usr/bin/osascript", "-e", 'tell application "{}" to quit'.format(args.clash_app)], 8)

    if vpn_state(args.vpn_service) not in {"Disconnected", "NotConfigured"}:
        run(["/usr/sbin/scutil", "--nc", "stop", args.vpn_service], 8)
        for _ in range(20):
            if vpn_state(args.vpn_service) in {"Disconnected", "NotConfigured"}:
                break
            time.sleep(0.5)

    blockers: List[str] = []
    if count_processes(args.claude_prefix) > 0:
        blockers.append("CLAUDE_RUNNING")
    if port_open(args.xray_port):
        blockers.append("XRAY_PORT_OPEN")
    if vpn_state(args.vpn_service) not in {"Disconnected", "NotConfigured"}:
        blockers.append("VPN_NOT_DISCONNECTED")
    if default_route().startswith("utun"):
        blockers.append("DEFAULT_ROUTE_ON_TUN")

    if blockers:
        print("SAFE_RESTART_BLOCKED " + ",".join(blockers), file=sys.stderr)
        return 75

    print("SAFE_RESTART_READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
