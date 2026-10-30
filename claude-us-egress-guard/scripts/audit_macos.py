#!/usr/bin/env python3
"""Read-only audit for the no-TUN macOS Claude egress design."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def run(args: List[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def value_after(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def route_interface() -> str:
    result = run(["/sbin/route", "-n", "get", "1.1.1.1"], 6)
    return value_after(result.stdout, r"^\s*interface:\s*(\S+)\s*$")


def proxy_configuration() -> Dict[str, Any]:
    result = run(["/usr/sbin/scutil", "--proxy"], 6)
    text = result.stdout
    return {
        "pac_enabled": value_after(text, r"^\s*ProxyAutoConfigEnable\s*:\s*(\d+)\s*$") == "1",
        "pac_url": value_after(text, r"^\s*ProxyAutoConfigURLString\s*:\s*(\S.*?)\s*$"),
        "http_enabled": value_after(text, r"^\s*HTTPEnable\s*:\s*(\d+)\s*$") == "1",
        "https_enabled": value_after(text, r"^\s*HTTPSEnable\s*:\s*(\d+)\s*$") == "1",
        "socks_enabled": value_after(text, r"^\s*SOCKSEnable\s*:\s*(\d+)\s*$") == "1",
    }


def day8_state() -> str:
    result = run(["/usr/sbin/scutil", "--nc", "status", "Day8"], 6)
    text = (result.stdout + "\n" + result.stderr).strip()
    for line in text.splitlines():
        candidate = line.strip()
        if candidate:
            return candidate
    return "NotConfigured"


def port_open(port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def json_from_curl(args: List[str], timeout: float = 14.0) -> Dict[str, Any]:
    result = run(args, timeout)
    if result.returncode != 0:
        return {"ok": False, "error": (result.stderr or result.stdout).strip()[:300]}
    try:
        parsed = json.loads(result.stdout)
    except ValueError:
        return {"ok": False, "error": "response was not JSON"}
    if not isinstance(parsed, dict):
        return {"ok": False, "error": "response was not an object"}
    return {
        "ok": True,
        "ip": str(parsed.get("ip", "")),
        "country": str(parsed.get("country", "")),
        "region": str(parsed.get("region", "")),
        "city": str(parsed.get("city", "")),
    }


def public_ip(proxy: Optional[str], timeout: float = 12.0) -> Dict[str, Any]:
    args = [
        "/usr/bin/curl",
        "-4",
        "-fsS",
        "--connect-timeout",
        "4",
        "--max-time",
        str(int(timeout)),
    ]
    if proxy:
        args.extend(["--proxy", proxy, "--noproxy", ""])
    else:
        args.extend(["--noproxy", "*"])
    args.append("https://ipinfo.io/json")
    return json_from_curl(args, timeout + 2)


def process_table() -> List[Dict[str, Any]]:
    result = run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,rgid=,gid=,args="], 8)
    rows: List[Dict[str, Any]] = []
    if result.returncode != 0:
        return rows
    for line in result.stdout.splitlines():
        parts = line.strip().split(maxsplit=4)
        if len(parts) != 5 or not all(part.isdigit() for part in parts[:4]):
            continue
        rows.append(
            {
                "pid": int(parts[0]),
                "ppid": int(parts[1]),
                "rgid": int(parts[2]),
                "gid": int(parts[3]),
                "args": parts[4],
            }
        )
    return rows


def claude_processes(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    application = [
        row
        for row in rows
        if row["args"].startswith("/Applications/Claude.app/Contents/")
    ]
    main_pids = {
        row["pid"]
        for row in rows
        if row["args"].startswith("/Applications/Claude.app/Contents/MacOS/Claude")
    }
    descendants: Set[int] = set(main_pids)
    for _ in range(12):
        added = {
            row["pid"]
            for row in rows
            if row["ppid"] in descendants and row["pid"] not in descendants
        }
        if not added:
            break
        descendants.update(added)

    descendant_rows = [row for row in rows if row["pid"] in descendants]
    selected = application + [
        row for row in descendant_rows if row["pid"] not in {r["pid"] for r in application}
    ]
    return {
        "running": bool(main_pids),
        "application_processes": [
            {
                "pid": row["pid"],
                "ppid": row["ppid"],
                "rgid": row["rgid"],
                "gid": row["gid"],
                "args": row["args"][:300],
            }
            for row in application
        ],
        "descendant_count": len(descendants),
        "selected_processes": [
            {
                "pid": row["pid"],
                "ppid": row["ppid"],
                "rgid": row["rgid"],
                "gid": row["gid"],
                "args": row["args"][:300],
            }
            for row in selected
        ],
    }


def launch_files() -> List[str]:
    roots = [
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    matches: List[str] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.plist")):
            lower = path.name.lower()
            if any(token in lower for token in ("claude", "xray", "egress", "chrome-policy")):
                matches.append(str(path))
    return matches


def pf_snapshot() -> Dict[str, Any]:
    info = run(["/sbin/pfctl", "-s", "info"], 6)
    anchors = run(["/sbin/pfctl", "-s", "anchors"], 6)
    return {
        "info_readable": info.returncode == 0,
        "enabled": bool(re.search(r"Status:\s*Enabled", info.stdout)),
        "info_error": "" if info.returncode == 0 else (info.stderr or info.stdout).strip()[:220],
        "anchors": [
            line.strip() for line in anchors.stdout.splitlines() if "claude" in line.lower()
        ],
    }


def build_report(args: argparse.Namespace) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    default_interface = route_interface()
    proxy_cfg = proxy_configuration()
    listener = port_open(args.proxy_port)
    day8 = day8_state()
    mihomo = run(["/usr/bin/pgrep", "-x", "verge-mihomo"], 4).returncode == 0
    processes = claude_processes(process_table())

    proxy_result: Dict[str, Any] = {"ok": False, "error": "network probe disabled"}
    direct_result: Dict[str, Any] = {"ok": False, "error": "network probe disabled"}
    if not args.no_network:
        proxy_result = public_ip(
            "http://127.0.0.1:{}".format(args.proxy_port),
            args.network_timeout,
        )
        direct_result = public_ip(None, args.network_timeout)

    if not default_interface:
        errors.append("DEFAULT_ROUTE_INTERFACE_UNKNOWN")
    elif default_interface.startswith("utun"):
        errors.append("DEFAULT_ROUTE_USES_TUN")

    if not listener:
        errors.append("LOCAL_PROXY_NOT_LISTENING")
    if day8 not in {"Disconnected", "NotConfigured", "Invalid"}:
        errors.append("DAY8_NOT_DISCONNECTED")
    if port_open(1088, timeout=0.5):
        errors.append("DAY8_PROXY_PORT_OPEN")
    if mihomo:
        errors.append("MIHOMO_RUNNING")
    if port_open(7897, timeout=0.5):
        warnings.append("CLASH_PROXY_PORT_OPEN")

    if not args.no_network:
        if not proxy_result.get("ok"):
            errors.append("PROXY_EGRESS_PROBE_FAILED")
        if args.expected_exit:
            if proxy_result.get("ok") and proxy_result.get("ip") != args.expected_exit:
                errors.append("PROXY_EXIT_MISMATCH")
        elif proxy_result.get("ok") and proxy_result.get("country") != "US":
            errors.append("PROXY_EXIT_NOT_US")
        if proxy_result.get("ok") and direct_result.get("ok"):
            if proxy_result.get("ip") == direct_result.get("ip"):
                errors.append("PROXY_AND_DIRECT_EXITS_MATCH")
        elif not direct_result.get("ok"):
            warnings.append("DIRECT_EGRESS_PROBE_UNAVAILABLE")

    if args.expected_gid is not None and processes["running"]:
        mismatches = [
            row
            for row in processes["selected_processes"]
            if row["rgid"] != args.expected_gid or row["gid"] != args.expected_gid
        ]
        if mismatches:
            errors.append("UNPROTECTED_CLAUDE_PROCESS_OR_DESCENDANT")

    if not proxy_cfg["pac_enabled"]:
        warnings.append("SYSTEM_PAC_NOT_ENABLED")
    if proxy_cfg["http_enabled"] or proxy_cfg["https_enabled"] or proxy_cfg["socks_enabled"]:
        warnings.append("NON_PAC_SYSTEM_PROXY_ENABLED")

    pf = pf_snapshot()
    if not pf["info_readable"]:
        warnings.append("PF_STATUS_REQUIRES_ADMIN_OR_IS_UNAVAILABLE")
    elif not pf["enabled"]:
        errors.append("PF_NOT_ENABLED")

    return {
        "checked_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "macos": run(["/usr/bin/sw_vers", "-productVersion"], 4).stdout.strip(),
        "default_route_interface": default_interface,
        "system_proxy": proxy_cfg,
        "proxy_port": args.proxy_port,
        "proxy_listening": listener,
        "day8_state": day8,
        "day8_proxy_open": port_open(1088, timeout=0.5),
        "mihomo_running": mihomo,
        "clash_proxy_open": port_open(7897, timeout=0.5),
        "proxy_egress": proxy_result,
        "direct_egress": direct_result,
        "claude": processes,
        "expected_gid": args.expected_gid,
        "launch_files": launch_files(),
        "pf": pf,
        "errors": errors,
        "warnings": warnings,
        "ok": not errors,
    }


def human_report(report: Dict[str, Any]) -> str:
    proxy_exit = report["proxy_egress"]
    direct_exit = report["direct_egress"]
    claude = report["claude"]
    lines = [
        "Claude US egress audit",
        "  macOS: {}".format(report["macos"] or "unknown"),
        "  checked: {}".format(report["checked_at"]),
        "  default route: {}".format(report["default_route_interface"] or "unknown"),
        "  system PAC: {}".format("enabled" if report["system_proxy"]["pac_enabled"] else "off"),
        "  local proxy :{}: {}".format(
            report["proxy_port"], "listening" if report["proxy_listening"] else "unavailable"
        ),
        "  Day8: {}".format(report["day8_state"]),
        "  Mihomo: {}".format("running" if report["mihomo_running"] else "stopped"),
        "  proxy exit: {}".format(
            "{} / {} / {}".format(proxy_exit.get("ip"), proxy_exit.get("country"), proxy_exit.get("city"))
            if proxy_exit.get("ok")
            else "unavailable ({})".format(proxy_exit.get("error", "unknown"))
        ),
        "  direct exit: {}".format(
            "{} / {} / {}".format(direct_exit.get("ip"), direct_exit.get("country"), direct_exit.get("city"))
            if direct_exit.get("ok")
            else "unavailable ({})".format(direct_exit.get("error", "unknown"))
        ),
        "  Claude: {}".format(
            "{} processes, {} process-tree entries".format(
                len(claude["application_processes"]), len(claude["selected_processes"])
            )
            if claude["running"]
            else "not running"
        ),
        "  result: {}".format("PASS" if report["ok"] else "FAIL"),
    ]
    if report["errors"]:
        lines.append("  errors: " + ", ".join(report["errors"]))
    if report["warnings"]:
        lines.append("  warnings: " + ", ".join(report["warnings"]))
    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--proxy-port",
        type=int,
        default=int(os.environ.get("CLAUDE_PROXY_PORT", "17891")),
        help="loopback HTTP proxy port (default: 17891)",
    )
    parser.add_argument(
        "--expected-exit",
        default=os.environ.get("CLAUDE_EXPECTED_EXIT", ""),
        help="expected proxy public IPv4 address",
    )
    parser.add_argument(
        "--expected-gid",
        type=int,
        default=int(os.environ["CLAUDE_EXPECTED_GID"])
        if os.environ.get("CLAUDE_EXPECTED_GID", "").isdigit()
        else None,
        help="expected real/effective Claude process GID",
    )
    parser.add_argument("--no-network", action="store_true", help="skip public-IP probes")
    parser.add_argument(
        "--network-timeout",
        type=float,
        default=12.0,
        help="per-request public-IP timeout in seconds",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero when any error is found",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    report = build_report(args)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(human_report(report))
    return 0 if report["ok"] or not args.strict else 2


if __name__ == "__main__":
    raise SystemExit(main())
