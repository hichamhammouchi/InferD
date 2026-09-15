# InferD - Setup

This guide brings up InferD on any linux host. InferD runs as one host-networked container. Traffic reaches it two ways: the
self-hosted services bind directly on their ports, and the five cloud API facades sit behind a TLS reverse proxy on :443.

### Requirements

The kernel egress guarantee sets a hard floor on where InferD can run:

- **Linux host.** Host networking and the iptables `owner` match are Linux-only;
  they do not work on Docker Desktop for macOS or Windows.
- **iptables (or the nft backend) with `CAP_NET_ADMIN`.** Needed to apply the
  OUTPUT rule. Locked-down managed-container platforms that deny it cannot
  provide the guarantee as written.
- **Host networking.** This is what preserves the real client IP. A Docker bridge
  network could block egress without host iptables, but every source address
  would collapse to the bridge gateway, losing attribution. That is a deliberate
  tradeoff, not a drop-in fallback.

Otherwise the requirement is just a Linux host with Docker and iptables.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Ubuntu 24.04 host | Container runs host-networked; ~2 vCPU / 4 GB RAM is enough |
| Docker + Compose | Installed in step 2 if not present |
| MaxMind licence key | Free at [maxmind.com](https://www.maxmind.com/en/geolite2/signup). Enables GeoIP country/ASN enrichment. Without it the honeypot still runs; country/ASN fields are left empty |
| A TLS certificate | Any certificate for the cloud-facade hostname. Self-signed is fine for a lab; a public CA is only needed for a publicly reachable deployment |

Set two variables once. `HOST` is where you reach the honeypot (`127.0.0.1` for a
local run, otherwise the machine's IP or hostname). `HONEYPOT_UID` is the numeric
UID the process runs as; 1001 is a fine default, but if that UID is already taken
on your host, pick another free one. This single value must match in three places
(the image build, the egress rule, and the data-dir ownership), and the steps
below all read it, so you only set it here.

```bash
HOST=127.0.0.1
HONEYPOT_UID=1001
```

---

## 1. Get the code onto the host

Copy this repository to the host and enter it. For a local run that is just a
clone or unzip. For a remote host, copy it there by whatever means you prefer
(`scp`, `rsync`, `git`), then continue on the host.

```bash
cd inferd/
```

---

## 2. System packages

```bash
apt-get update
apt-get install -y \
  curl ca-certificates gnupg lsb-release \
  iptables iptables-persistent netfilter-persistent \
  jq sqlite3 unzip

# Docker (skip if already installed)
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
```

---

## 3. Directories

No host user is needed. The honeypot user lives inside the container; on the host
the iptables rule and file ownership refer to `$HONEYPOT_UID` by number, so the
data directory just needs to be writable by that UID.

```bash
mkdir -p /data/db /data/raw /data/logs
chown -R $HONEYPOT_UID:$HONEYPOT_UID /data
chmod 750 /data /data/db /data/raw /data/logs

touch /data/db/honeypot.db
chown $HONEYPOT_UID:$HONEYPOT_UID /data/db/honeypot.db

mkdir -p /etc/inferd
chmod 755 /etc/inferd

mkdir -p /usr/share/GeoIP
```

---

## 4. MaxMind GeoLite2 (optional)

Enables the country and ASN fields. Skip if you do not have a key; the honeypot
runs without it.

```bash
MAXMIND_KEY=<your-key>
TMP=$(mktemp -d)
for ed in GeoLite2-City GeoLite2-ASN; do
  curl -fsSL \
    "https://download.maxmind.com/app/geoip_download?edition_id=${ed}&license_key=${MAXMIND_KEY}&suffix=tar.gz" \
    -o "$TMP/${ed}.tar.gz"
  tar -xzf "$TMP/${ed}.tar.gz" -C "$TMP"
  find "$TMP" -name "${ed}.mmdb" -exec cp {} /usr/share/GeoIP/ \;
done
chmod 644 /usr/share/GeoIP/*.mmdb
rm -rf "$TMP"
```

---

## 5. Runtime config

```bash
cat > /etc/inferd/inferd.env << 'EOF'
DATA_DIR=/data
DB_PATH=/data/db/honeypot.db
RAW_LOG_DIR=/data/raw
POOL_DIR=/app/honeypot/response_pools
CANARY_INJECTION_RATE=0.30
RATE_LIMIT_SOFT_RPM=60
RATE_LIMIT_HARD_RPM=300
RATE_LIMIT_LATENCY_MS=2000
MAX_STREAMING_PER_IP=8
MAX_REQUEST_BODY_BYTES=33554432
STORE_RAW_AUTH_KEYS=false
EOF

chown root:root /etc/inferd/inferd.env
chmod 644 /etc/inferd/inferd.env
```

---

## 6. Egress isolation (required)

This is the kernel-level safety boundary. It drops every outbound connection
from `$HONEYPOT_UID` regardless of what any emulator does, so a tool argument,
URL, or injected payload can never leave the host. Loopback and established
connections stay open so the reverse proxy and responses work.

```bash
apply_egress_rules() {
  local cmd="$1" uid="$HONEYPOT_UID" chain="INFERD_EGRESS"
  $cmd -N "$chain" 2>/dev/null || true
  $cmd -F "$chain"
  $cmd -A "$chain" -o lo -j ACCEPT
  $cmd -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $cmd -A "$chain" -j DROP
  while $cmd -C OUTPUT -m owner --uid-owner "$uid" -j "$chain" 2>/dev/null; do
    $cmd -D OUTPUT -m owner --uid-owner "$uid" -j "$chain"
  done
  $cmd -I OUTPUT 1 -m owner --uid-owner "$uid" -j "$chain"
}
apply_egress_rules iptables
apply_egress_rules ip6tables
netfilter-persistent save

# Verify
iptables -L OUTPUT -n --line-numbers | head -20
iptables -L INFERD_EGRESS -n --line-numbers
```

The `$HONEYPOT_UID` here must equal the UID baked into the image in step 9.

---

## 7. TLS for the cloud facades

The five cloud API facades sit behind a TLS reverse proxy on :443, so you need a
certificate for the facade hostname. Any certificate works. Point the nginx
config at the cert and key paths, then load it.

**(optional) self-signed, for a lab or local run:**
```bash
mkdir -p /etc/inferd/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /etc/inferd/tls/key.pem -out /etc/inferd/tls/cert.pem \
  -subj "/CN=${HOST}"
```

**(optional) public CA, only for a publicly reachable deployment:** obtain a
certificate for your hostname with your CA of choice and reference it the same
way. A public certificate requires a resolvable public DNS name, which is a
deployment decision, not a requirement of InferD.

`nginx.conf` already points at `/etc/inferd/tls/cert.pem` and `key.pem`, so the
self-signed step above works as-is. For a public CA, swap those two paths. Start
nginx however you run it (host package or a container). The self-hosted services
do not use TLS; they bind directly.

---

## 8. Firewall (optional)

Only if you are exposing the host and want to limit open ports. Skip for a local
run.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 443/tcp                                 # cloud facades (TLS)
for p in 11434 8001 8888 8080 5000 6333 7860 4000 18789; do ufw allow $p/tcp; done
ufw enable
```

---

## 9. Build and start

```bash
docker build --build-arg HONEYPOT_UID=$HONEYPOT_UID -t inferd:latest .
docker compose config
docker compose up -d
docker compose ps

# All 10 process groups (1 cloud group + 9 self-hosted) should be RUNNING
docker exec inferd supervisorctl status
```

---

## 10. Honeytokens (optional)

Generate decoy API keys. The CLI supports the `openai`, `anthropic`, `gemini`,
and `generic` formats, one key per invocation.

```bash
docker exec inferd python3 /app/scripts/tokens.py generate --format openai    --label "lab-01"
docker exec inferd python3 /app/scripts/tokens.py generate --format anthropic --label "lab-01"
docker exec inferd python3 /app/scripts/tokens.py list
```

Seed tokens only in controlled locations where credential-harvesting tools are
known to collect, in line with your institution's ethics or IRB guidance. Do not
plant them in ways that could entrap or mislead uninvolved third parties.

---

## 11. Verify it works

```bash
# Cloud facade (through the TLS proxy). -k accepts a self-signed cert.
curl -sk https://${HOST}/v1/models | python3 -m json.tool | head -5
curl -sk -X POST https://${HOST}/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | python3 -m json.tool | grep protocolVersion

# Self-hosted surface (direct ports)
curl -s http://${HOST}:11434/api/version
curl -s http://${HOST}:8001/v1/models | python3 -m json.tool | grep '"id"' | head -3
curl -s http://${HOST}:6333/collections | python3 -m json.tool

# Events landing in the database
sqlite3 /data/db/honeypot.db \
  'SELECT service, COUNT(*) FROM events GROUP BY service ORDER BY 2 DESC'
```

Port 8001 is an InferD-designated direct port for the vLLM facade; it is not
claimed to be the conventional upstream vLLM default.

## View logs

```bash
tail -f /data/logs/openai.log
tail -f /data/raw/$(date +%Y-%m-%d).jsonl | python3 -m json.tool
docker logs inferd --tail=50 -f
```
