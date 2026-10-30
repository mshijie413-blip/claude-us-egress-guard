# Installation Guide

This is a staged reference implementation, not a one-click installer. Every
root-level action needs a rollback. Never migrate by running two TUN owners.

## Prerequisites

- macOS with a stable physical network service.
- Claude Desktop.
- Xray-core. Do not commit the downloaded binary.
- Optional Chromium managed policy and a signing/ownership strategy suitable
  for the organization.
- Administrative access only for PF, system PAC and LaunchDaemon work.

Use placeholders until each layer passes:

```text
VPS_ADDRESS=vps.example.com
VPS_PORT=8443
LOCAL_HTTP_PROXY=127.0.0.1:17891
EXPECTED_EXIT=203.0.113.10
CLAUDE_GID=62001
```

`203.0.113.10` is a documentation address. Replace it only in the private local
configuration.

## 1. VPS

1. Install Xray from its official release process.
2. Create a dedicated VLESS identity and REALITY key pair on the VPS.
3. Keep the server configuration owned by root and mode `0600`.
4. Permit only the proxy TCP port required by the deployment. Do not expose the
   Xray API or database services publicly.
5. Enable the OS firewall, updates and SSH key-only administration.
6. Record the VPS public IPv4 and confirm it geolocates to the intended U.S.
   region using multiple sources.

Do not copy a private key into prompts, shell history, repository files or the
client machine. The client needs only the public REALITY parameters.

Start from [xray-server.example.json](../assets/xray-server.example.json) on the
VPS:

```bash
chmod 600 /usr/local/etc/xray/config.json
xray run -test -config /usr/local/etc/xray/config.json
```

Create or review the service definition for the distribution, enable it, and
check:

```bash
systemctl status xray
ss -lntp | grep ':8443'
journalctl -u xray --no-pager -n 100
```

The VPS should expose one intended proxy port and SSH administration from
restricted source networks. Do not expose the Xray API or add an open proxy
inbound. Confirm that the VPS provider and region are suitable for the use case
and that access complies with the destination service's terms and applicable
law.

## 2. Local Xray

Create a private directory:

```bash
install -d -m 0700 "$HOME/Library/Application Support/ClaudeVPSDirect"
```

Start from [client.example.json](../assets/client.example.json). Replace the
placeholders locally, then:

```bash
chmod 600 "$HOME/Library/Application Support/ClaudeVPSDirect/client.json"
xray run -test -config "$HOME/Library/Application Support/ClaudeVPSDirect/client.json"
```

Keep both HTTP and SOCKS listeners on loopback. Disable SOCKS UDP unless a
specific approved use case requires it.

Create a user LaunchAgent from
[seattle-xray.plist.example](../assets/seattle-xray.plist.example), then test:

```bash
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/com.example.claude-us-xray.plist"
launchctl kickstart -k "gui/$(id -u)/com.example.claude-us-xray"
curl -4 -fsS --proxy http://127.0.0.1:17891 \
  --noproxy '' https://ipinfo.io/json
```

The first acceptance criterion is a verified U.S. public exit. A listening port
by itself proves nothing.

## 3. PAC

Render a deployment PAC:

```bash
python3 scripts/render_pac.py \
  --proxy 127.0.0.1:17891 \
  --protected-domain claude.ai \
  --protected-domain anthropic.com \
  --direct-domain feishu.cn \
  --output claude_split.pac
```

Review the result. Public hosts not explicitly protected or direct must resolve
to the local proxy; there must be no public `DIRECT` fallback.

Install the PAC as a root-owned file and configure the active primary network
service to use it. Keep a backup of the prior proxy settings.

## 4. Chrome Managed Policy

Start from
[com.google.Chrome.plist.example](../assets/com.google.Chrome.plist.example).

Requirements:

- `ProxyMode = pac_script`
- `ProxyPacUrl` points to the local PAC file
- `ProxyPacMandatory = true`
- No unmanaged secondary proxy can replace the policy

If macOS clears files under `/Library/Managed Preferences` after reboot, use a
root LaunchDaemon that validates and restores only this policy file. Do not let
the guard change routes or VPN state.

Validate with a real Chrome-controlled probe, not only by reading the plist.

## 5. Dedicated Group and Setgid Launcher

Choose a numeric GID not used by the system. Compile
[claude_egress_gid_launcher.c](../assets/claude_egress_gid_launcher.c) with the
current interactive UID and chosen GID:

```bash
cc -O2 -Wall -Wextra \
  -DEXPECTED_UID="$(id -u)" \
  -DEGRESS_GID=62001 \
  -DPROXY_PORT=17891 \
  -o claude_egress_gid_launcher \
  assets/claude_egress_gid_launcher.c
```

The installed launcher must be root-owned, group-owned by the dedicated group
and setgid:

```text
root:<CLAUDE_GID> mode 2755
```

It must set the real and effective GID before `execve`, set proxy variables and
launch Claude with loopback-only proxy arguments and QUIC disabled.

Test identity without starting Claude:

```bash
claude_egress_gid_launcher --selftest
claude_egress_gid_launcher --probe us
claude_egress_gid_launcher --probe direct   # expected to fail
claude_egress_gid_launcher --probe day8     # expected to fail
```

## 6. PF

Start from [pf_rules.example.conf](../assets/pf_rules.example.conf). The intended
order is:

1. Permit the dedicated group to loopback proxy port only.
2. Drop all other TCP and UDP from that group.

Load the rules into a dedicated nested PF anchor and verify them:

```bash
sudo pfctl -n -f /path/to/pf_rules.example.conf
sudo pfctl -a com.example.claude_egress_guard -f /path/to/pf_rules.example.conf
sudo pfctl -a com.example.claude_egress_guard -sr
```

PF rule loading and reference-count tokens are operationally fragile. A
root-owned guard should restore only its own anchor, preserve the previous
system state and expose an explicit rollback command. Never flush the complete
PF ruleset as a shortcut.

## 7. Protected Launcher

Adapt [launch_claude_protected.sh](../assets/launch_claude_protected.sh).

The wrapper should:

1. Reject an already-running unguarded Claude instance.
2. Verify PF and proxy health.
3. Launch through the setgid binary.
4. Wait for the main process and several Helpers.
5. Verify real/effective GID, proxy arguments and PF runtime state.
6. Quit or refuse the new instance on any mismatch.

Never fall back to `open -a Claude` when a check fails.

## 8. Acceptance

Run all checks before allowing normal use:

```bash
python3 scripts/audit_macos.py \
  --expected-exit <verified-U.S.-IPv4> \
  --expected-gid <CLAUDE_GID> \
  --strict
```

Required results:

- Default route is the physical interface.
- Day8/Clash/Mihomo are disconnected or stopped.
- Xray is loopback-only.
- Proxy and direct public exits differ.
- PAC and PF checks pass.
- Claude main process and every descendant share the dedicated GID.
- A direct PF probe from the dedicated GID fails.
- An allowed probe to the local proxy succeeds.

## Rollback

Before enabling the launcher:

1. Back up old PF anchors without flushing the live ruleset.
2. Back up the old system PAC and Chrome policy.
3. Keep the Xray LaunchAgent label and plist.
4. Record previous proxy settings for every active network service.
5. Ensure Claude is stopped before removing its group rule.

Uninstall in reverse order: Claude, protected group/PF anchor, Chrome policy,
system PAC, Xray LaunchAgent, client files. Verify the physical default route
and normal direct browsing before deleting backups.
