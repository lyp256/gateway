#!/usr/bin/env sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NFT_CONF="${NFT_CONF:-$ROOT_DIR/config/dns-proxy.conf}"
FWMARK="${FWMARK:-0x1}"
ROUTE_TABLE="${ROUTE_TABLE:-100}"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "this script must be run as root" >&2
        exit 1
    fi
}

ensure_ip_rule() {
    if ! ip rule show | grep -Fq "fwmark $FWMARK lookup $ROUTE_TABLE"; then
        ip rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE"
    fi
}

ensure_local_route() {
    if ! ip route show table "$ROUTE_TABLE" | grep -Fq "local 0.0.0.0/0 dev lo"; then
        ip route add local 0.0.0.0/0 dev lo table "$ROUTE_TABLE"
    fi
}

require_root

sysctl -w net.ipv4.ip_forward=1 >/dev/null
if nft list table inet dns_proxy >/dev/null 2>&1; then
    nft delete table inet dns_proxy
fi
nft -f "$NFT_CONF"
ensure_ip_rule
ensure_local_route

echo "dns proxy enabled"
echo "nft config: $NFT_CONF"
echo "fwmark: $FWMARK"
echo "route table: $ROUTE_TABLE"
