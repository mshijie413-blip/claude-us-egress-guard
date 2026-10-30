---
name: claude-us-egress-guard
description: Audit, operate, or safely adapt a no-TUN macOS egress guard that keeps Claude Desktop and managed Chrome traffic on a self-hosted U.S. Xray path while leaving ordinary domestic and LAN traffic direct. Use for Claude proxy failures, split-routing drift, GID/PF/PAC checks, safe launch or shutdown, and publishing this design without secrets.
---

# Claude US Egress Guard

## Outcome

Keep Claude's network path observable and fail-closed:

```text
Claude -> filesystem-only local proxy -> self-hosted VPS -> external service
```

Use the physical interface for ordinary traffic. Do not add a second TUN layer or weaken unrelated applications to fix Claude.

## Start With Evidence

Before changing anything, run:

```bash
python3 scripts/audit_macos.py --strict
```

Use `--expected-exit <verified-U.S.-IPv4>` and `--expected-gid <gid>` when the deployment provides them. Add `--json` for machine-readable output and `--no-network` when outbound probes are not authorized.

Read [architecture.md](references/architecture.md) when explaining trust boundaries or failure modes. Read [diagnostics.md](references/diagnostics.md) for a live incident.

## Preserve These Invariants

- Keep exactly one owner of the default route: the physical interface.
- Keep the Xray listener loopback-only.
- Resolve PAC ProxyMode to the local proxy for protected public hosts; never fall back to public `DIRECT`.
- Verify the public egress through the proxy, not merely that the local port is open.
- Verify the Claude main process, Electron Helpers, Node services and spawned local tools share the intended real and effective GID.
- Refuse to start Claude if any required check fails.
- Treat a successful browser login as unrelated to native app authentication; app token exchange can use a different network path.

## Change Discipline

Audit is read-only. Do not install, restart, stop, flush PF, change routes, alter a PAC, or edit VPN configuration unless the user explicitly authorizes that mutation for the current turn.

For installation or adaptation, read [installation.md](references/installation.md). Stage and validate each layer separately:

1. VPS and local Xray.
2. Local proxy egress.
3. PAC and browser policy.
4. Process identity and PF.
5. Protected launcher.
6. Shutdown/restart preparation.

Keep rollback points for every root-owned file. Never run two TUN/VPN owners during migration.

## Daily Operation

Read [operations.md](references/operations.md) for the exact startup, shutdown, Chrome and reboot behavior. The short version:

- Launch Claude only through the protected entry point.
- Chrome normally needs no per-page action.
- Stop Claude normally before stopping its proxy.
- Prepare VPN/network extensions before restart or shutdown.
- If the U.S. exit cannot be verified, stop Claude rather than falling back to direct access.

## Secrets and Publication

Never include these in the skill, repository, prompts or logs:

- Xray UUID, REALITY private key, proxy credentials or subscription URLs.
- SSH private keys, database passwords, cookies, bearer tokens or API keys.
- Real customer records, company data or unredacted packet captures.

Create a client template from a real configuration with:

```bash
python3 scripts/sanitize_xray_config.py /path/to/client.json
```

Before publishing, run:

```bash
python3 scripts/check_public_safety.py .
python3 -m py_compile scripts/*.py
```

## Boundaries

This skill protects process egress. It does not make a deployment anonymous, stop data already sent to a model, secure a compromised Mac/VPS, authorize access to company systems, or make SSH/database traffic pass through an HTTP proxy automatically.

Do not broaden Claude's network access merely to make one tool work. Design a separate least-privilege gateway with authentication, field/row restrictions, masking, rate limits, audit logs and an emergency stop.
