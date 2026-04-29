#!/bin/bash
# AuthGuard - Launch Dashboard
# Opens the AuthGuard SOC dashboard in the default browser.
# The authguard service should already be running via systemd.

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${GREEN}  AuthGuard SOC Dashboard${NC}"
echo "  ──────────────────────────"

# Check authguard service
if systemctl is-active --quiet authguard; then
    echo -e "  ${GREEN}●${NC} authguard service running"
else
    echo -e "  ${YELLOW}●${NC} authguard service not running — starting..."
    sudo systemctl start authguard
    sleep 2
fi

# Check apache
if systemctl is-active --quiet apache2; then
    echo -e "  ${GREEN}●${NC} apache2 running"
else
    echo -e "  ${YELLOW}●${NC} apache2 not running — starting..."
    sudo systemctl start apache2
    sleep 1
fi

# Check socket
if [ -S /run/authguard/authguard.sock ]; then
    echo -e "  ${GREEN}●${NC} unix socket ready"
else
    echo -e "  ${RED}✗${NC} socket not found — try: sudo systemctl restart authguard"
    exit 1
fi

echo ""
echo -e "  Opening ${GREEN}https://localhost/dashboard${NC}"
echo ""

xdg-open https://localhost/dashboard 2>/dev/null || \
firefox https://localhost/dashboard 2>/dev/null || \
google-chrome https://localhost/dashboard 2>/dev/null || \
echo "  Open your browser and go to: https://localhost/dashboard"
