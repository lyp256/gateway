#!/usr/bin/env bash
# Start tunnel-client under delve (headless) inside the test netns for remote
# debugging from .vscode/launch.json.
#
# The script intentionally runs as the task's own process and traps INT/TERM:
# "Terminate Task" in VS Code only signals this process, and without cleanup the
# dlv/target tree would be orphaned (especially after the target crashes, dlv
# keeps it stopped and headless). The trap tears the whole tree down instead.

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

NS="${TESTNS:-test}"
TUNNEL_URL="${TUNNEL_URL:-http://198.19.20.21}"
DLV_BIN="${DLV_BIN:-$(command -v dlv)}"
CLEAN="$ROOT/scripts/tunnel-client-debug-clean.sh"

cleanup() {
    "$CLEAN"
    exit 0
}
trap cleanup INT TERM

sudo ip netns exec "$NS" env DEBUG_ADDR=":12080" "$DLV_BIN" exec ./bin/tunnel-client \
    --headless --listen=:2345 --api-version=2 -- --url="$TUNNEL_URL" &
wait "$!"
