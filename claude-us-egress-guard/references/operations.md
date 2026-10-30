# Operations

## Start Claude

Use only the protected entry point. It should run the read-only preflight,
repair only approved prerequisites, verify egress and then launch Claude through
the setgid helper.

Do not open `/Applications/Claude.app` from Finder, Spotlight or the Dock.

After launch:

```bash
python3 scripts/audit_macos.py --expected-gid 62001 --strict
```

All Claude application and Helper processes should have real and effective GID
`62001`.

## Close Claude

1. Save work.
2. Quit Claude normally with `Command-Q`.
3. Leave Xray running if Claude will be reopened soon.
4. Stop Xray only after Claude has fully exited.

Never stop the proxy while Claude is still performing a model request.

## Chrome

Chrome uses persistent managed policy. It does not need a script for every tab.

Run the Chrome verification or restart entry point when:

- macOS restarted.
- Chrome policy changed.
- The local proxy was restarted.
- Chrome shows `ERR_PROXY_CONNECTION_FAILED`.
- A managed-policy update is expected.

If Chrome policy is mandatory and the local proxy is down, protected public
pages should fail rather than fall back to direct networking.

## Reboot or Shutdown

Before restart:

1. Quit Claude.
2. Stop the dedicated Xray LaunchAgent.
3. Quit Clash/Mihomo if present.
4. Disconnect any legacy VPN/network extension that previously caused kernel
   routing instability.
5. Confirm the default route is not on `utun*`.
6. Only then reboot or shut down.

`safe_restart_prepare.py` is a read-and-stop workflow. It must fail closed when
Claude, the proxy port, the VPN client or the default route remains in an unsafe
state.

## Normal Status

Use:

```bash
python3 scripts/audit_macos.py --json
```

Key fields:

```text
default_route_interface       en0 / en1, never utun*
proxy_listening               true
proxy_exit                    expected U.S. address
direct_exit                   different from proxy_exit
claude_all_gids_protected     true
day8_proxy_open               false
mihomo_running                false
```

## When Protection Fails

1. Keep Claude closed.
2. Do not disable PF, PAC or LuLu to "test."
3. Confirm the physical default route and local proxy.
4. Confirm the VPS exit on two independent sources.
5. Re-run the audit.
6. Repair one layer at a time with a recorded rollback point.

If only Chrome fails, do not alter Claude's PF rule. If only Claude fails, do not
weaken Chrome policy. Isolate the failing control plane.

## SSH and Databases

The default implementation intentionally blocks direct LAN and non-HTTP traffic
from Claude's dedicated GID. Do not add broad exceptions for SSH or database
ports.

Use a separately authorized gateway. Keep credentials outside Claude, expose
only fixed operations and return the minimum necessary result. A network guard
cannot make submitted customer data safe.
