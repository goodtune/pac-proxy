#!/bin/sh
set -e

# Make systemd see the new or updated unit. Enabling and starting the
# service is left to the system administrator:
#   systemctl enable --now pac-proxy.service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
