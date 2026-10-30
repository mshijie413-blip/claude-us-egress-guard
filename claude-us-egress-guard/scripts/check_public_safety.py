#!/usr/bin/env python3
"""Reject common secret and deployment-identifier leaks before publishing."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple


TEXT_SUFFIXES = {
    "",
    ".c",
    ".command",
    ".conf",
    ".example",
    ".json",
    ".md",
    ".pac",
    ".plist",
    ".py",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
}

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----"
)
TOKEN_RES = [
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
]
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:password|passwd|token|secret|api[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*[\"']?([^\s\"'#,]{8,})"
)


def is_allowed_example_ip(value: str) -> bool:
    # 1.1.1.1 is intentionally used as a route-connectivity probe in audit and
    # troubleshooting instructions. It is not deployment-specific data.
    if value == "1.1.1.1":
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return (
        address.is_loopback
        or address.is_unspecified
        or address in ipaddress.ip_network("192.0.2.0/24")
        or address in ipaddress.ip_network("198.51.100.0/24")
        or address in ipaddress.ip_network("203.0.113.0/24")
    )


def should_scan(path: Path, root: Path) -> bool:
    if ".git" in path.parts or "__pycache__" in path.parts:
        return False
    if path.is_symlink() or not path.is_file():
        return False
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return False
    try:
        if path.stat().st_size > 2_000_000:
            return False
    except OSError:
        return False
    return True


def inspect(path: Path, root: Path) -> List[Tuple[str, int, str]]:
    findings: List[Tuple[str, int, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [(str(path.relative_to(root)), 0, "unreadable: " + str(exc))]

    placeholders = (
        "REPLACE_",
        "REDACTED",
        "example.com",
        "[REDACTED]",
        "YOUR_",
    )
    for line_number, line in enumerate(text.splitlines(), 1):
        if PRIVATE_KEY_RE.search(line):
            findings.append(
                (str(path.relative_to(root)), line_number, "private key material")
            )
        for pattern in TOKEN_RES:
            if pattern.search(line):
                findings.append(
                    (str(path.relative_to(root)), line_number, "access token pattern")
                )
        if UUID_RE.search(line) and not any(marker in line for marker in placeholders):
            findings.append(
                (str(path.relative_to(root)), line_number, "UUID-like deployment identifier")
            )
        for match in IPV4_RE.finditer(line):
            if not is_allowed_example_ip(match.group(0)) and not any(
                marker in line for marker in placeholders
            ):
                findings.append(
                    (
                        str(path.relative_to(root)),
                        line_number,
                        "non-example IPv4 address: " + match.group(0),
                    )
                )
        assignment = ASSIGNMENT_RE.search(line)
        if assignment:
            value = assignment.group(1)
            if not any(marker.lower() in value.lower() for marker in placeholders):
                findings.append(
                    (
                        str(path.relative_to(root)),
                        line_number,
                        "non-placeholder secret assignment",
                    )
                )
    return findings


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print("SAFETY_SCAN_ERROR: not a directory: {}".format(root), file=sys.stderr)
        return 2

    findings: List[Tuple[str, int, str]] = []
    for path in sorted(root.rglob("*")):
        if should_scan(path, root):
            findings.extend(inspect(path, root))

    if findings:
        for path, line, message in findings:
            print("{}:{}: {}".format(path, line, message))
        print("PUBLIC_SAFETY_FAILED findings={}".format(len(findings)))
        return 1
    print("PUBLIC_SAFETY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
