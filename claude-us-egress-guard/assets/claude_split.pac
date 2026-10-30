// Fail-closed PAC for Claude US Egress Guard.
// Managed browser policy must set ProxyPacMandatory=true.
// Public hosts resolve to the loopback proxy with no DIRECT fallback.

var LOCAL_PROXY = "PROXY 127.0.0.1:17891";
var PROTECTED_DOMAINS = [
  "anthropic.com",
  "anthropicapi.com",
  "anthropicusercontent.com",
  "claude.ai",
  "claude.com",
  "claudemcpcontent.com",
  "claudeusercontent.com"
];
var DIRECT_DOMAINS = [
  "feishu.cn",
  "larksuite.com",
  "larkoffice.com",
  "feishu.net"
];

function domainMatches(host, domain) {
  return host === domain || dnsDomainIs(host, "." + domain);
}

function isDomains(host, domains) {
  for (var i = 0; i < domains.length; i++) {
    if (domainMatches(host, domains[i])) return true;
  }
  return false;
}

function isPrivateOrLocal(host) {
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
}

function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\.$/, "");

  if (isDomains(host, PROTECTED_DOMAINS)) return LOCAL_PROXY;
  if (isPrivateOrLocal(host)) return "DIRECT";
  if (isDomains(host, DIRECT_DOMAINS)) return "DIRECT";
  if (dnsDomainIs(host, ".cn")) return "DIRECT";
  return LOCAL_PROXY;
}
