#!/bin/sh
set -e

# RPM passes 1 and DEB passes "upgrade" when the package is being replaced
# by a newer version; leave the service running in that case.
case "$1" in
    1|upgrade) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop pac-proxy.service 2>/dev/null || true
    systemctl disable pac-proxy.service 2>/dev/null || true
fi
