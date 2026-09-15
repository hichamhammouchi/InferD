#!/usr/bin/env bash
# =============================================================================
# InferD - Idempotent bootstrap script
# Run as root on a fresh Ubuntu 24.04 / 26.04 server.
#
# Usage:
#   sudo bash deploy.sh [--maxmind-key <key>] [--domain <name> --email <addr>] [--skip-certbot] [--harden-ssh]
#
# Options:
#   --maxmind-key KEY   MaxMind GeoLite2 licence key (free account at maxmind.com)
#   --domain NAME       Public DNS name for the TLS facade
#   --email ADDRESS     ACME contact address used with --domain
#   --skip-certbot      Keep the generated self-signed bootstrap certificate
#   --harden-ssh        Move SSH to port 2222 and apply the documented SSH hardening
#
# What this script does:
#   1.  Optionally hardens SSH and moves it to port 2222
#   2.  Installs system packages (Docker, Nginx, certbot, iptables-persistent)
#   3.  Creates honeypot system user (UID 1001)
#   4.  Creates directory structure under /data and /etc/inferd
#   5.  Downloads MaxMind GeoLite2 database (requires licence key)
#   6.  Copies Nginx config and obtains Let's Encrypt certificates
#   7.  Installs iptables egress isolation rules (UID 1001 → DROP)
#   8.  Builds and starts Docker container
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# Colour output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${GREEN}== $* ==${NC}"; }

# Argument parsing
MAXMIND_KEY=""
DOMAIN=""
EMAIL=""
SKIP_CERTBOT=false
HARDEN_SSH=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --maxmind-key) MAXMIND_KEY="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --skip-certbot) SKIP_CERTBOT=true; shift ;;
    --harden-ssh) HARDEN_SSH=true; shift ;;
    *) error "Unknown argument: $1" ;;
  esac
done

# Pre-flight checks
[[ $EUID -eq 0 ]] || error "Run as root: sudo bash deploy.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

info "Script dir: $SCRIPT_DIR"
info "Repo dir  : $REPO_DIR"

# ====
step "1. SSH hardening"
# ====
if [[ "$HARDEN_SSH" == true ]]; then
  SSHD_CONF="/etc/ssh/sshd_config"
  if ! grep -q "^Port 2222" "$SSHD_CONF"; then
    info "Configuring SSH on port 2222"
    sed -i 's/^Port /#Port /g' "$SSHD_CONF"
    echo "Port 2222" >> "$SSHD_CONF"
    cat >> "$SSHD_CONF" << 'EOF'

# InferD hardening
PasswordAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
AllowTcpForwarding no
EOF
    systemctl restart ssh
    info "SSH now on port 2222"
  else
    info "SSH already on port 2222 - skipping"
  fi
else
  info "SSH configuration unchanged (use --harden-ssh to opt in)"
fi

# ====
step "2. System packages"
# ====
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release openssl \
  nginx certbot python3-certbot-nginx \
  iptables iptables-persistent netfilter-persistent \
  jq sqlite3 unzip git \
  > /dev/null

# Docker (official repo)
if ! command -v docker &>/dev/null; then
  info "Installing Docker"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null
  systemctl enable --now docker
  info "Docker installed"
else
  info "Docker already present - skipping engine install"
fi
if ! docker compose version &>/dev/null; then
  info "Installing Docker Compose plugin"
  apt-get update -qq
  apt-get install -y -qq docker-compose-plugin > /dev/null
fi

# ====
step "3. Honeypot system user (UID 1001)"
# ====
if ! id honeypot &>/dev/null; then
  groupadd --gid 1001 honeypot
  useradd  --uid 1001 --gid 1001 --system --no-create-home --shell /usr/sbin/nologin honeypot
  info "Created user honeypot (UID 1001)"
else
  info "User honeypot already exists - skipping"
fi

# ====
step "4. Directory structure"
# ====
mkdir -p /data/db /data/raw /data/logs /etc/inferd /usr/share/GeoIP /var/www/inferd

chown -R honeypot:honeypot /data
chmod 750 /data /data/db /data/raw /data/logs

# Pre-create DB file owned by UID 1001 so SQLite writes succeed.
# If created by Docker/root at first boot the process gets a read-only DB.
touch /data/db/honeypot.db
chown 1001:1001 /data/db/honeypot.db

# /etc/inferd: owned root, world-traversable so container UID 1001 can reach the env file.
chown root:honeypot /etc/inferd
chmod 755 /etc/inferd

info "Directories ready"

# ====
step "5. MaxMind GeoLite2"
# ====
GEOIP_CITY="/usr/share/GeoIP/GeoLite2-City.mmdb"
GEOIP_ASN="/usr/share/GeoIP/GeoLite2-ASN.mmdb"
if [[ -n "$MAXMIND_KEY" ]]; then
  info "Downloading GeoLite2 City and ASN databases"
  TMP_DIR=$(mktemp -d)
  for edition in GeoLite2-City GeoLite2-ASN; do
    curl -fsSL \
      "https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${MAXMIND_KEY}&suffix=tar.gz" \
      -o "${TMP_DIR}/${edition}.tar.gz"
    tar -xzf "${TMP_DIR}/${edition}.tar.gz" -C "${TMP_DIR}"
    find "${TMP_DIR}" -name "${edition}.mmdb" -exec cp {} /usr/share/GeoIP/ \;
  done
  rm -rf "${TMP_DIR}"
  chmod 644 "$GEOIP_CITY" "$GEOIP_ASN"
  info "GeoLite2 databases installed"
elif [[ -f "$GEOIP_CITY" && -f "$GEOIP_ASN" ]]; then
  info "GeoLite2 databases already present - skipping download"
else
  warn "GeoLite2 City/ASN databases are incomplete; GeoIP enrichment will be partial or disabled."
fi

# ====
step "6. Environment config"
# ====
ENV_FILE="/etc/inferd/inferd.env"
if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" << 'EOF'
# InferD runtime config - edit as needed
# This file is read by pydantic-settings at startup.

# Data paths (defaults match Dockerfile; don't change unless you remap volumes)
DATA_DIR=/data
DB_PATH=/data/db/honeypot.db
RAW_LOG_DIR=/data/raw
POOL_DIR=/app/honeypot/response_pools

# Canary injection rate (fraction of honeytoken responses that embed a canary)
CANARY_INJECTION_RATE=0.30

# Rate limiting
RATE_LIMIT_SOFT_RPM=60
RATE_LIMIT_HARD_RPM=300
RATE_LIMIT_LATENCY_MS=2000
MAX_STREAMING_PER_IP=8
MAX_REQUEST_BODY_BYTES=33554432
STORE_RAW_AUTH_KEYS=false

EOF
  chown root:honeypot "$ENV_FILE"
  chmod 644 "$ENV_FILE"
  info "Created $ENV_FILE"
else
  info "Config file already exists - preserving"
fi

# ====
step "7. Nginx"
# ====

# Landing page
if [[ -d "$REPO_DIR/site" ]]; then
  cp -r "$REPO_DIR/site/." /var/www/inferd/
  info "Copied landing page to /var/www/inferd"
fi

# Nginx config
NGINX_AVAILABLE="/etc/nginx/sites-available/inferd"
NGINX_ENABLED="/etc/nginx/sites-enabled/inferd"

mkdir -p /etc/inferd/tls
if [[ ! -s /etc/inferd/tls/cert.pem || ! -s /etc/inferd/tls/key.pem ]]; then
  info "Generating bootstrap self-signed TLS certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout /etc/inferd/tls/key.pem -out /etc/inferd/tls/cert.pem \
    -subj "/CN=${DOMAIN:-localhost}" >/dev/null 2>&1
fi

cp "$REPO_DIR/nginx/nginx.conf" "$NGINX_AVAILABLE"
if [[ -n "$DOMAIN" ]]; then
  sed -i "s/server_name _;/server_name ${DOMAIN};/g" "$NGINX_AVAILABLE"
fi
ln -sf "$NGINX_AVAILABLE" "$NGINX_ENABLED" 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl enable --now nginx
systemctl reload nginx
info "Nginx config installed and reloaded"

if [[ "$SKIP_CERTBOT" == false && -n "$DOMAIN" ]]; then
  [[ -n "$EMAIL" ]] || error "--email is required when --domain is used without --skip-certbot"
  info "Obtaining Let's Encrypt certificate for $DOMAIN"
  certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "$EMAIL"
  ln -sfn "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /etc/inferd/tls/cert.pem
  ln -sfn "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" /etc/inferd/tls/key.pem
  nginx -t
  systemctl reload nginx
elif [[ "$SKIP_CERTBOT" == false ]]; then
  warn "No --domain supplied; keeping the self-signed TLS certificate."
else
  info "Using the self-signed TLS certificate (--skip-certbot)"
fi

# ====
step "8. iptables egress isolation"
# ====
# Rule: all outbound traffic from UID 1001 (honeypot) is DROPPED, EXCEPT:
#   - Loopback (127.0.0.0/8)       - needed for uvicorn → Nginx → uvicorn
#   - Already-established sessions - needed for uvicorn to send responses
#   - DNS on port 53                - blocked too (no resolver calls from honeypot)
#
# CRITICAL: These rules prevent the honeypot from being used as a relay.
#
# Applied to both IPv4 (iptables) and IPv6 (ip6tables).

apply_rules() {
  local cmd="$1" chain="INFERD_EGRESS"

  $cmd -N "$chain" 2>/dev/null || true
  $cmd -F "$chain"
  $cmd -A "$chain" -o lo -j ACCEPT
  $cmd -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $cmd -A "$chain" -j DROP

  while $cmd -C OUTPUT -m owner --uid-owner 1001 -j "$chain" 2>/dev/null; do
    $cmd -D OUTPUT -m owner --uid-owner 1001 -j "$chain"
  done
  $cmd -I OUTPUT 1 -m owner --uid-owner 1001 -j "$chain"

  info "  $cmd egress chain applied"
}


apply_rules iptables
apply_rules ip6tables

# Persist rules across reboots
netfilter-persistent save
info "iptables egress isolation active and persisted"

# ====
step "9. Docker container"
# ====
cd "$REPO_DIR"

info "Building Docker image"
docker build --build-arg HONEYPOT_UID=1001 -t inferd:latest .

info "Starting container"
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d

info "Container status:"
docker compose ps

# Wait for services to respond
sleep 3
if curl -sf http://127.0.0.1:11434/api/version > /dev/null 2>&1; then
  info "Ollama emulator responding ✓"
fi
if curl -sf http://127.0.0.1:8000/v1/models > /dev/null 2>&1; then
  info "OpenAI emulator responding ✓"
fi

# ====
step "Deployment complete"
# ====

echo ""
echo "  Honeypot surfaces:"
echo "    https://${DOMAIN:-<host>}              OpenAI / Anthropic / Gemini / Assistants / MCP"
echo "    http://<ip>:11434                Ollama"
echo "    http://<ip>:6333                 Qdrant"
echo "    http://<ip>:8888                 Jupyter"
echo "    http://<ip>:8080                 HuggingFace TGI"
echo "    http://<ip>:5000                 MLflow"
echo "    http://<ip>:7860                 Gradio"
echo ""
echo "  Next steps:"
echo "    1. Generate honeytokens:  python3 $REPO_DIR/scripts/tokens.py generate"
echo "    2. View logs:             tail -f /data/raw/\$(date +%Y-%m-%d).jsonl"
echo "    3. Query database:        sqlite3 /data/db/honeypot.db"
echo ""

