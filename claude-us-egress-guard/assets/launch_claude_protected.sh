#!/bin/zsh
# Template: start Claude only after the read-only guard passes.
set -euo pipefail

GUARD_HOME="${CLAUDE_GUARD_HOME:-$HOME/Library/Application Support/ClaudeUSEgressGuard}"
LAUNCHER="${CLAUDE_LAUNCHER:-/Library/Application Support/ClaudePFGuard/claude_egress_gid_launcher}"
EXPECTED_GID="${CLAUDE_EXPECTED_GID:-62001}"
EXPECTED_EXIT="${CLAUDE_EXPECTED_EXIT:-}"
AUDIT="$GUARD_HOME/audit_macos.py"

if pgrep -f '^/Applications/Claude.app/Contents/' >/dev/null 2>&1; then
  echo "CLAUDE_ALREADY_RUNNING: quit it before using the protected launcher" >&2
  exit 74
fi

[[ -x "$LAUNCHER" && -f "$AUDIT" ]] || {
  echo "GUARD_FILES_MISSING" >&2
  exit 73
}

audit_args=(--expected-gid "$EXPECTED_GID" --strict)
[[ -n "$EXPECTED_EXIT" ]] && audit_args+=(--expected-exit "$EXPECTED_EXIT")
python3 "$AUDIT" "${audit_args[@]}" || {
  echo "PREFLIGHT_FAILED: Claude was not started" >&2
  exit 72
}

nohup "$LAUNCHER" >>"$GUARD_HOME/protected-launch.log" 2>&1 < /dev/null &
launcher_pid=$!

for _ in {1..36}; do
  pids=($(pgrep -f '^/Applications/Claude.app/Contents/' || true))
  (( ${#pids[@]} >= 3 )) && break
  sleep 0.5
done

if (( ${#pids[@]} < 3 )); then
  kill "$launcher_pid" 2>/dev/null || true
  echo "CLAUDE_START_GRACE_FAILED" >&2
  exit 75
fi

for pid in "${pids[@]}"; do
  gids=($(ps -p "$pid" -o rgid=,gid=))
  if [[ "${gids[1]}" != "$EXPECTED_GID" || "${gids[2]}" != "$EXPECTED_GID" ]]; then
    osascript -e 'tell application "Claude" to quit' >/dev/null 2>&1 || true
    echo "UNPROTECTED_CLAUDE_PROCESS pid=$pid" >&2
    exit 76
  fi
done

echo "CLAUDE_PROTECTED_GID_READY gid=$EXPECTED_GID processes=${#pids[@]}"
