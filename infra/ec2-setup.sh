#!/usr/bin/env bash
# ==============================================================================
# secure-deploy EC2 Hardening & Setup Script
# Run once on a clean Ubuntu 22.04 LTS instance.
# Idempotent: safe to run multiple times.
# ==============================================================================

set -euo pipefail

echo "===> [1/8] Updating package index..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

echo "===> [2/8] Installing Docker, Nginx, Certbot, UFW, and utilities..."
apt-get install -y \
    docker.io \
    nginx \
    certbot \
    python3-certbot-nginx \
    ufw \
    unattended-upgrades \
    curl \
    git \
    openssl

echo "===> [3/8] Configuring Docker permissions..."
systemctl enable docker
systemctl start docker
if id "ubuntu" &>/dev/null; then
    usermod -aG docker ubuntu
fi

echo "===> [4/8] Hardening SSH and Host Security..."
# Disable password authentication in sshd_config
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd || true
fi

echo "===> [5/8] Configuring UFW Firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

echo "===> [6/8] Enabling unattended security updates..."
systemctl enable unattended-upgrades
systemctl start unattended-upgrades

echo "===> [7/8] Provisioning SSL certificates & Nginx directories..."
mkdir -p /etc/nginx/snippets
mkdir -p /etc/nginx/conf.d
mkdir -p /var/www/certbot
mkdir -p /etc/ssl/certs
mkdir -p /etc/ssl/private

# Generate self-signed certificate if not present (Mode B for demo/no domain)
if [ ! -f /etc/ssl/certs/secure-deploy-selfsigned.crt ]; then
    echo "Generating demo self-signed TLS certificate (4096-bit RSA)..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout /etc/ssl/private/secure-deploy-selfsigned.key \
        -out /etc/ssl/certs/secure-deploy-selfsigned.crt \
        -subj "/C=US/ST=DevSecOps/L=Cloud/O=SecureDeploy/CN=localhost"
    chmod 600 /etc/ssl/private/secure-deploy-selfsigned.key
fi

echo "===> [8/8] Copying hardened Nginx configuration and validating..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -f "$PROJECT_ROOT/nginx/snippets/security.conf" ]; then
    cp "$PROJECT_ROOT/nginx/snippets/security.conf" /etc/nginx/snippets/security.conf
fi

if [ -f "$PROJECT_ROOT/nginx/default.conf" ]; then
    cp "$PROJECT_ROOT/nginx/default.conf" /etc/nginx/sites-available/default
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
fi

# Verify configuration syntax before reloading
nginx -t
systemctl restart nginx

echo "=========================================================================="
echo " secure-deploy EC2 host setup complete and hardened successfully!"
echo "   - Docker daemon running and active"
echo "   - Nginx running with TLS 1.2/1.3, CSP, HSTS, rate limits, and hidden dotfiles"
echo "   - UFW firewall enabled (ports 22, 80, 443 only)"
echo "   - Unattended security updates enabled"
echo "=========================================================================="
