#!/usr/bin/env python3
"""Render a fail-closed PAC for the no-TUN Claude egress design."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional


DEFAULT_PROTECTED = [
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "anthropicapi.com",
    "claudeusercontent.com",
    "claudemcpcontent.com",
    "anthropicusercontent.com",
]

DEFAULT_DIRECT = [
    "feishu.cn",
    "larksuite.com",
    "larkoffice.com",
    "feishu.net",
    "qq.com",
    "tencent.com",
    "weixin.qq.com",
    "taobao.com",
    "tmall.com",
    "alipay.com",
    "alibaba.com",
    "aliyuncs.com",
    "jd.com",
    "baidu.com",
    "bilibili.com",
    "zhihu.com",
    "weibo.com",
    "xiaohongshu.com",
    "douban.com",
    "meituan.com",
    "dianping.com",
    "bytedance.com",
    "toutiao.com",
    "douyin.com",
]


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("empty domain")
    if "://" in domain or "/" in domain or ":" in domain:
        raise ValueError("use a hostname only, without scheme, path or port: " + value)
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        raise ValueError("invalid hostname: " + value)
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        raise ValueError("invalid hostname: " + value)
    return domain


def parse_proxy(value: str) -> str:
    match = re.fullmatch(r"(127\.0\.0\.1):([1-9][0-9]{0,4})", value.strip())
    if not match:
        raise ValueError("--proxy must be a loopback HTTP proxy, for example 127.0.0.1:17891")
    port = int(match.group(2))
    if port > 65535:
        raise ValueError("proxy port is out of range")
    return "{}:{}".format(match.group(1), port)


def render(proxy: str, protected: List[str], direct: List[str]) -> str:
    protected_json = json.dumps(protected, ensure_ascii=True, indent=2)
    direct_json = json.dumps(direct, ensure_ascii=True, indent=2)
    return """// Fail-closed PAC for Claude US Egress Guard.
// Managed browser policy must set ProxyPacMandatory=true.
// Public hosts resolve to the loopback proxy with no DIRECT fallback.

var LOCAL_PROXY = "PROXY {proxy}";
var PROTECTED_DOMAINS = {protected};
var DIRECT_DOMAINS = {direct};

function domainMatches(host, domain) {{
  return host === domain || dnsDomainIs(host, "." + domain);
}}

function isDomains(host, domains) {{
  for (var i = 0; i < domains.length; i++) {{
    if (domainMatches(host, domains[i])) return true;
  }}
  return false;
}}

function isPrivateOrLocal(host) {{
  return host === "localhost" ||
    isPlainHostName(host) ||
    shExpMatch(host, "127.*") ||
    shExpMatch(host, "10.*") ||
    shExpMatch(host, "192.168.*") ||
    shExpMatch(host, "172.16.*") ||
    shExpMatch(host, "172.17.*") ||
    shExpMatch(host, "172.18.*") ||
    shExpMatch(host, "172.19.*") ||
    shExpMatch(host, "172.2?.*") ||
    shExpMatch(host, "172.30.*") ||
    shExpMatch(host, "172.31.*") ||
    dnsDomainIs(host, ".local") ||
    dnsDomainIs(host, ".lan");
}}

function FindProxyForURL(url, host) {{
  host = host.toLowerCase().replace(/\\.$/, "");

  // Protected hosts are checked first so a user-managed direct domain cannot
  // accidentally override the Claude/Anthropic path.
  if (isDomains(host, PROTECTED_DOMAINS)) return LOCAL_PROXY;

  if (isPrivateOrLocal(host)) return "DIRECT";
  if (isDomains(host, DIRECT_DOMAINS)) return "DIRECT";
  if (dnsDomainIs(host, ".cn")) return "DIRECT";

  // Every other public hostname must use the local proxy. If it is down,
  // browser access fails instead of silently escaping through a direct route.
  return LOCAL_PROXY;
}}
""".format(proxy=proxy, protected=protected_json, direct=direct_json)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default="127.0.0.1:17891")
    parser.add_argument(
        "--protected-domain",
        action="append",
        default=[],
        help="repeatable protected public domain",
    )
    parser.add_argument(
        "--direct-domain",
        action="append",
        default=[],
        help="repeatable domestic or business domain that may go direct",
    )
    parser.add_argument(
        "--without-default-domestic",
        action="store_true",
        help="do not include the built-in domestic direct domain list",
    )
    parser.add_argument("--output", type=Path, help="write the PAC to this path")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        proxy = parse_proxy(args.proxy)
        protected = sorted(
            {normalize_domain(domain) for domain in DEFAULT_PROTECTED + args.protected_domain}
        )
        base_direct = [] if args.without_default_domestic else DEFAULT_DIRECT
        direct = sorted(
            {normalize_domain(domain) for domain in base_direct + args.direct_domain}
        )
        overlap = sorted(set(protected) & set(direct))
        if overlap:
            raise ValueError("protected and direct domains overlap: " + ", ".join(overlap))
        text = render(proxy, protected, direct)
    except ValueError as exc:
        print("PAC_RENDER_ERROR: {}".format(exc), file=sys.stderr)
        return 2

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        args.output.chmod(0o644)
        print("PAC_RENDERED {}".format(args.output))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
