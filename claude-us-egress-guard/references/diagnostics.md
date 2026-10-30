# Diagnostics

All commands below are read-only unless explicitly marked.

## First Snapshot

```bash
python3 scripts/audit_macos.py --json
date
uptime
sysctl -n kern.boottime
route -n get 1.1.1.1
scutil --proxy
lsof -nP -iTCP:17891 -sTCP:LISTEN
ps -axo pid,ppid,rgid,gid,etime,comm,args |
  grep -E 'Claude|Xray|verge-mihomo|PacketTunnel'
```

Do not treat an open port as a valid proxy. Test the actual exit through it.

## Claude Process Tree

```bash
pids=$(pgrep -f '^/Applications/Claude.app/Contents/' | tr '\n' ' ')
ps -o pid=,ppid=,rgid=,gid=,args= -p $pids
```

Main process, Renderer, GPU, Network Service, Node Service and local tool
children should all inherit the dedicated GID. A single unprotected descendant
invalidates the guarantee.

## Normal Quit Versus Hang Versus Crash

- Normal quit: application log contains `beforeQuit`, cleanup handlers and a
  clean process exit.
- Hang: a `*.hang` diagnostic report records an unresponsive process and thread
  stacks.
- Crash: a crash report records a fatal signal or exception.
- Kernel watchdog or panic: inspect `/Library/Logs/DiagnosticReports` and
  `log show` for `watchdog`, `panic` and `configd`.

Example:

```bash
find "$HOME/Library/Logs/DiagnosticReports" \
  /Library/Logs/DiagnosticReports \
  -maxdepth 1 -type f -mtime -2 -print

tail -n 300 "$HOME/Library/Logs/Claude/main.log"
```

## Network Extension Deadlock

Look for a deadlock chain in a hang report:

```bash
rg -n 'Deadlock|Blocked by Deadlock|PacketTunnel|dlil_input|configd' \
  /Library/Logs/DiagnosticReports/*.hang
```

Record each participant and thread. Do not conclude that the application listed
as blocked is the cause; identify the lock owner cycle.

## PF

```bash
sudo pfctl -s info
sudo pfctl -a <anchor-name> -sr
```

If the anchor is missing, stop protected Claude before repairing anything. Do
not run `pfctl -F all` or replace unrelated anchors.

## PAC and Browser

```bash
scutil --proxy
plutil -p "/Library/Managed Preferences/<user>/com.google.Chrome.plist"
```

Then use the running browser to request a harmless public endpoint through its
actual network stack. Policy-file existence alone does not prove the browser
honors it.

## Xray

```bash
lsof -nP -iTCP:17891 -sTCP:LISTEN
curl -4 -fsS --proxy http://127.0.0.1:17891 \
  --noproxy '' https://ipinfo.io/json
tail -n 100 \
  "$HOME/Library/Application Support/ClaudeVPSDirect/xray-service.log"
```

Check two independent IP services when possible. A failing lookup service is
not automatically evidence that the proxy is down.

## macOS Unified Logs

Narrow by time and process:

```bash
log show --style compact \
  --start '2026-01-01 10:00:00' \
  --end '2026-01-01 10:05:00' \
  --predicate 'process == "Claude"'
```

For network-extension failures, also inspect `nehelper`, `nesessionmanager`,
`configd`, `kernel` and the extension bundle identifier.

## Evidence Rules

- Separate observation from inference.
- Compare the fault time with uptime and the last reboot.
- Do not attribute a graceful application quit to a network fault without a
  matching stack or error.
- Do not publish raw logs without removing tokens, hostnames, usernames, internal
  IPs and user/account identifiers.
