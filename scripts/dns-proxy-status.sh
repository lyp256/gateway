#!/usr/bin/env sh

set -eu

FWMARK="${FWMARK:-0x1}"
ROUTE_TABLE="${ROUTE_TABLE:-100}"

echo "== nft table =="
if nft list table inet dns_proxy >/dev/null 2>&1; then
    nft list table inet dns_proxy
else
    echo "table inet dns_proxy is not loaded"
fi

echo
echo "== ip rules matching fwmark =="
ip rule show | grep -F "fwmark $FWMARK" || true

echo
echo "== routes in table $ROUTE_TABLE =="
ip route show table "$ROUTE_TABLE" || true
