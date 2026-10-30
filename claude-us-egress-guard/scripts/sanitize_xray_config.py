#!/usr/bin/env python3
"""Create a publishable Xray client template from a private config."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


SECRET_KEYS = {
    "id",
    "password",
    "pass",
    "user",
    "username",
    "email",
    "token",
    "secret",
    "privatekey",
    "private_key",
    "publickey",
    "public_key",
    "shortid",
    "short_id",
    "servername",
    "server_name",
    "address",
    "host",
    "path",
    "spiderx",
}

PLACEHOLDERS = {
    "id": "REPLACE_WITH_VLESS_UUID",
    "password": "REPLACE_WITH_PASSWORD",
    "pass": "REPLACE_WITH_PASSWORD",
    "user": "REPLACE_WITH_USER",
    "username": "REPLACE_WITH_USER",
    "email": "REPLACE_WITH_EMAIL",
    "token": "REPLACE_WITH_TOKEN",
    "secret": "REPLACE_WITH_SECRET",
    "privatekey": "REPLACE_WITH_PRIVATE_KEY",
    "private_key": "REPLACE_WITH_PRIVATE_KEY",
    "publickey": "REPLACE_WITH_REALITY_PUBLIC_KEY",
    "public_key": "REPLACE_WITH_REALITY_PUBLIC_KEY",
    "shortid": "REPLACE_WITH_REALITY_SHORT_ID",
    "short_id": "REPLACE_WITH_REALITY_SHORT_ID",
    "servername": "REPLACE_WITH_TLS_SERVER_NAME",
    "server_name": "REPLACE_WITH_TLS_SERVER_NAME",
    "address": "vps.example.com",
    "host": "REPLACE_WITH_HOST",
    "path": "REPLACE_WITH_PATH",
    "spiderx": "/",
}

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
    )


def sanitize(value: Any, key: str = "") -> Any:
    normalized_key = key.lower()
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for child_key, child_value in value.items():
            result[child_key] = sanitize(child_value, child_key)
        return result
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if normalized_key in SECRET_KEYS:
        return PLACEHOLDERS.get(normalized_key, "REPLACE_WITH_VALUE")
    if normalized_key == "interface":
        return "en0"
    if isinstance(value, str):
        value = UUID_RE.sub(PLACEHOLDERS["id"], value)
        value = IPV4_RE.sub(
            lambda match: "203.0.113.10" if is_public_ip(match.group(0)) else match.group(0),
            value,
        )
    return value


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="private Xray client JSON")
    parser.add_argument("--output", type=Path, help="write template to this path")
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace the output file if it already exists",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.output and args.output.exists() and not args.force:
        print("SANITIZE_ERROR: output exists; pass --force to replace", file=sys.stderr)
        return 2
    try:
        source = json.loads(args.source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("SANITIZE_ERROR: {}".format(exc), file=sys.stderr)
        return 2
    if not isinstance(source, dict):
        print("SANITIZE_ERROR: top-level JSON must be an object", file=sys.stderr)
        return 2
    text = json.dumps(sanitize(source), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        args.output.chmod(0o600)
        print("XRAY_TEMPLATE_WRITTEN {}".format(args.output))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
