# Architecture and Threat Model

## Goals

The design keeps Claude traffic on one controlled public egress without turning
the whole Mac into a VPN:

- Claude Desktop and its descendants cannot open arbitrary outbound sockets.
- The local Xray process owns the only allowed Claude network destination.
- Domestic, LAN and ordinary browser traffic can remain direct.
- Any prerequisite failure blocks Claude instead of silently using a public
  direct connection.

## Components

| Layer | Responsibility | Typical evidence |
|---|---|---|
| Application | Claude starts with loopback proxy arguments and no QUIC | `ps -ww -p <pid> -o args=` |
| Process identity | Main app and descendants use one dedicated real/effective GID | `ps -o rgid=,gid=` |
| Kernel PF | Allows that GID to reach only `127.0.0.1:17891` | `pfctl -a <anchor> -sr` |
| Local proxy | Xray listens on loopback and exits through the VPS | `lsof -nP -iTCP:17891` plus public-IP probe |
| Browser policy | Managed PAC sends protected public hosts to loopback | managed policy plus real Chrome probe |
| Control plane | Launch, repair, audit and shutdown wrappers | status JSON and exit codes |

## Traffic Flow

```text
Claude main process / Helpers / local tools
  -> 127.0.0.1:17891
  -> Xray on physical interface
  -> encrypted VLESS/REALITY session
  -> self-hosted VPS
  -> Anthropic and other permitted destinations
```

The VPS is a trust boundary. It can see connection metadata and terminates the
proxy protocol. Harden it, restrict access and never store unrelated secrets on
it.

## Why No TUN

A TUN client changes kernel routing and can interact with other network
extensions. A dual-TUN or TUN-plus-filter failure can block packet input and
network configuration services for every application on the Mac. This design
keeps routing in user space and uses PF only for process-scoped egress.

That does not prove TUN software is inherently unsafe. It reflects a deliberate
operational choice: avoid two components competing for kernel routing on a
single workstation.

## Fail-Closed Semantics

The protected launcher may start Claude only when all of these hold:

1. The default route is a physical interface.
2. The local proxy is listening.
3. Its public exit matches the expected U.S. address or country policy.
4. The managed PAC and browser policy are present.
5. The PF group rule is loaded.
6. The launcher has the expected setgid identity.
7. No Claude process is already running outside the expected GID.

If any check fails, do not launch Claude and do not fall back to direct egress.

## Threat Model

Protected:

- Accidental direct connections from normal Claude Desktop processes.
- QUIC or UDP bypass attempts from the guarded process group.
- Browser PAC drift and ordinary system-proxy fallback.
- Accidental use of an inactive or non-U.S. proxy path when a pinned address is
  configured.

Not protected:

- Data intentionally returned by tools, pasted into prompts or uploaded to the
  model.
- A compromised macOS account, VPS, Xray binary or Claude binary.
- Native protocols that ignore HTTP proxy variables unless separately routed.
- A user or administrator intentionally running Claude outside the launcher.
- Availability. A proxy outage is expected to stop protected access.
- Anonymity. VPS and network providers still observe metadata.

## SSH and Database Boundaries

SSH and database wire protocols do not automatically use
`--proxy-server=http://127.0.0.1:17891`. Direct LAN access also bypasses the
U.S. VPS and reveals a local private or public source IP to the destination.

If such tools are required, design a separate gateway with:

- A fixed destination allowlist.
- Read-only credentials stored outside the model context.
- Field/row filtering and irreversible masking.
- Per-request human approval for sensitive records.
- Rate, row and time limits.
- Complete audit logs and a one-step kill switch.

Do not solve a tool-access failure by globally disabling PF or granting the
Claude GID unrestricted LAN access.
