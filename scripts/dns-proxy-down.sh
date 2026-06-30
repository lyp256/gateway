#!/usr/bin/env sh

set -eu

FWMARK="${FWMARK:-0x1}"
ROUTE_TABLE="${ROUTE_TABLE:-100}"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "this script must be run as root" >&2
        exit 1
    fi
}

require_root

while ip rule show | grep -Fq "fwmark $FWMARK lookup $ROUTE_TABLE"; do
    ip rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE"
done

if ip route show table "$ROUTE_TABLE" | grep -Fq "local 0.0.0.0/0 dev lo"; then
    ip route del local 0.0.0.0/0 dev lo table "$ROUTE_TABLE"
fi

if nft list table inet dns_proxy >/dev/null 2>&1; then
    nft delete table inet dns_proxy
fi

echo "dns proxy disabled"
