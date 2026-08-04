#!/usr/bin/env bash
# Tear down a leftover tunnel-client debug tree (dlv + the stopped target).
# Used by the debug task's signal handler and as the postDebugTask so nothing
# is left orphaned after the session ends (especially after the target crashes).

set -u

# The dlv/target tree runs as root (under sudo) and the target is usually
# stopped under the debugger (ignores TERM), so kill it with sudo + KILL.
# The [-.] brackets stop pkill from matching our own command line.
sudo pkill -KILL -f 'bin/tunnel[-]client --url=' 2>/dev/null || true
sudo pkill -KILL -f 'dlv exec ./bin/tunnel[-]client' 2>/dev/null || true
sudo pkill -KILL -f 'ip netns exec test env DEBUG_ADDR=:12080' 2>/dev/null || true
