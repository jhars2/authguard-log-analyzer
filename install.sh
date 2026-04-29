#!/bin/bash
# ============================================================
#  AuthGuard — Install Script
#  Sets up the full AuthGuard SOC dashboard stack on Debian/Ubuntu.
#  Run as root or with sudo.
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

info()    { echo -e "  ${BLUE}→${NC} $1"; }
success() { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}!${NC} $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; exit 1; }

echo ""
echo -e "${BOLD}  AuthGuard SOC Dashboard — Installer${NC}"
echo "  ────────────────────────────────────"
echo ""

# ── Root check ──
if [ "$EUID" -ne 0 ]; then
    fail "Please run as root: sudo bash install.sh"
fi

# ── OS check ──
if ! command -v apt &>/dev/null; then
    fail "This installer requires a Debian/Ubuntu-based system."
fi

# ── Dependencies ──
echo -e "${BOLD}  [1/7] Installing dependencies${NC}"
apt update -q
apt install -y -q \
    apache2 \
    python3 \
    python3-flask \
    python3-gunicorn \
    libapache2-mod-security2 \
    modsecurity-crs \
    openssl
success "Dependencies installed"

# ── System user ──
echo ""
echo -e "${BOLD}  [2/7] Creating system user${NC}"
if id "authguard" &>/dev/null; then
    warn "User 'authguard' already exists — skipping"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin authguard
    success "Created system user 'authguard'"
fi
usermod -aG systemd-journal authguard
usermod -aG authguard www-data
success "Group memberships set"

# ── App directory ──
echo ""
echo -e "${BOLD}  [3/7] Setting up app directory${NC}"
mkdir -p /opt/authguard
cp log_analyzer.py /opt/authguard/
cp app.py /opt/authguard/
cp launch.sh /opt/authguard/
chmod +x /opt/authguard/launch.sh
chown -R authguard:authguard /opt/authguard
success "App files installed to /opt/authguard"

# ── Directories ──
mkdir -p /var/log/authguard
chown authguard:authguard /var/log/authguard
success "Log directory created"

# ── SSL certificate ──
echo ""
echo -e "${BOLD}  [4/7] Generating SSL certificate${NC}"
if [ -f /etc/ssl/certs/apache-selfsigned.crt ]; then
    warn "Certificate already exists — skipping"
else
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/apache-selfsigned.key \
        -out /etc/ssl/certs/apache-selfsigned.crt \
        -subj "/C=US/ST=State/L=City/O=AuthGuard/CN=localhost" \
        -quiet
    success "Self-signed certificate generated"
fi

# ── Apache hardening ──
echo ""
echo -e "${BOLD}  [5/7] Configuring Apache${NC}"

# Modules
a2enmod ssl proxy proxy_http headers security2 &>/dev/null
a2dismod autoindex status negotiation env 2>/dev/null || true

# ServerName
if ! grep -q "^ServerName" /etc/apache2/apache2.conf; then
    echo "ServerName localhost" >> /etc/apache2/apache2.conf
fi

# Remove directory listing
sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' \
    /etc/apache2/apache2.conf 2>/dev/null || true

# Security config
cat > /etc/apache2/conf-available/security.conf << 'EOF'
ServerTokens Prod
ServerSignature Off
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header always set Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:;"
</IfModule>
EOF
a2enconf security &>/dev/null

# ModSecurity
if [ -f /etc/modsecurity/modsecurity.conf-recommended ]; then
    cp /etc/modsecurity/modsecurity.conf-recommended \
       /etc/modsecurity/modsecurity.conf
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' \
        /etc/modsecurity/modsecurity.conf
fi

# HTTP → HTTPS redirect
cat > /etc/apache2/sites-available/000-default.conf << 'EOF'
<VirtualHost *:80>
    ServerName localhost
    Redirect permanent / https://localhost/
</VirtualHost>
EOF

# HTTPS + proxy site
cat > /etc/apache2/sites-available/authguard.conf << 'EOF'
<VirtualHost *:443>
    ServerName localhost
    SSLEngine on
    SSLCertificateFile      /etc/ssl/certs/apache-selfsigned.crt
    SSLCertificateKeyFile   /etc/ssl/private/apache-selfsigned.key

    ProxyPreserveHost On
    ProxyPass /dashboard unix:/run/authguard/authguard.sock|http://localhost/
    ProxyPassReverse /dashboard unix:/run/authguard/authguard.sock|http://localhost/
</VirtualHost>
EOF

a2ensite default-ssl authguard &>/dev/null
success "Apache configured and hardened"

# ── systemd service ──
echo ""
echo -e "${BOLD}  [6/7] Installing systemd service${NC}"
cat > /etc/systemd/system/authguard.service << 'EOF'
[Unit]
Description=AuthGuard SOC Dashboard
After=network.target

[Service]
User=authguard
Group=authguard
WorkingDirectory=/opt/authguard
RuntimeDirectory=authguard
RuntimeDirectoryMode=0755
ExecStart=/usr/bin/python3 -m gunicorn \
    --workers 2 \
    --bind unix:/run/authguard/authguard.sock \
    --umask 007 \
    --log-level info \
    --access-logfile /var/log/authguard/access.log \
    --error-logfile /var/log/authguard/error.log \
    app:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable authguard
systemctl restart authguard
systemctl restart apache2
success "Service installed and started"

# ── Verify ──
echo ""
echo -e "${BOLD}  [7/7] Verifying installation${NC}"
sleep 3

if systemctl is-active --quiet authguard; then
    success "authguard service: running"
else
    warn "authguard service: not running — check: journalctl -u authguard"
fi

if systemctl is-active --quiet apache2; then
    success "apache2: running"
else
    warn "apache2: not running — check: journalctl -u apache2"
fi

if [ -S /run/authguard/authguard.sock ]; then
    success "unix socket: ready"
else
    warn "unix socket: not found"
fi

echo ""
echo -e "${BOLD}  Installation complete.${NC}"
echo ""
echo "  Dashboard : https://localhost/dashboard"
echo "  Launch    : bash /opt/authguard/launch.sh"
echo "  Logs      : /var/log/authguard/"
echo "  Service   : sudo systemctl status authguard"
echo ""
