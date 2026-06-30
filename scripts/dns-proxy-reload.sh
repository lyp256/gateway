#!/usr/bin/env sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

"$ROOT_DIR/dns-proxy-down.sh"
"$ROOT_DIR/dns-proxy-up.sh"
