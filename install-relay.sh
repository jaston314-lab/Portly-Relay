#!/usr/bin/env bash
set -euo pipefail

# Required env vars:
#   BRAIN_URL
#   RELAY_SERVICE_KEY
# Optional:
#   RELAY_HOSTNAME (default: hostname)
#   RELAY_ENDPOINT_HOST (default: empty)
#   RELAY_REPO (default: https://github.com/jaston314-lab/Portly-Relay.git)
#   RELAY_DIR (default: /opt/portly-relay)

if [[ -z "${BRAIN_URL:-}" ]]; then
  echo "ERROR: BRAIN_URL is required" >&2
  exit 1
fi

if [[ -z "${RELAY_SERVICE_KEY:-}" ]]; then
  echo "ERROR: RELAY_SERVICE_KEY is required" >&2
  exit 1
fi

RELAY_REPO="${RELAY_REPO:-https://github.com/jaston314-lab/Portly-Relay.git}"
RELAY_DIR="${RELAY_DIR:-/opt/portly-relay}"
RELAY_HOSTNAME="${RELAY_HOSTNAME:-$(hostname)}"
RELAY_ENDPOINT_HOST="${RELAY_ENDPOINT_HOST:-}"

PUBLIC_IP="$(curl -fsSL https://api.ipify.org || true)"
if [[ -z "$PUBLIC_IP" ]]; then
  PUBLIC_IP="$(hostname -I | awk '{print $1}')"
fi

if [[ -z "$PUBLIC_IP" ]]; then
  echo "ERROR: Could not determine public IP" >&2
  exit 1
fi

echo "[1/8] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io docker-compose-v2 git wireguard wireguard-tools curl
apt-get install -y docker-buildx-plugin || true
systemctl enable --now docker

echo "[2/8] Fetching relay repository..."
if [[ -d "$RELAY_DIR/.git" ]]; then
  git -C "$RELAY_DIR" pull --ff-only
else
  rm -rf "$RELAY_DIR"
  git clone "$RELAY_REPO" "$RELAY_DIR"
fi

echo "[3/8] Writing relay .env..."
cat >"$RELAY_DIR/.env" <<EOF
BRAIN_URL="${BRAIN_URL}"
RELAY_SERVICE_KEY="${RELAY_SERVICE_KEY}"
RELAY_SYNC_INTERVAL_SECONDS="10"
RELAY_REQUEST_TIMEOUT_SECONDS="10"
EOF

echo "[4/8] Generating relay WireGuard private key if missing..."
if [[ ! -s "$RELAY_DIR/relay_privatekey" ]]; then
  umask 077
  wg genkey > "$RELAY_DIR/relay_privatekey"
fi
chmod 600 "$RELAY_DIR/relay_privatekey"
RELAY_PUBLIC_KEY="$(wg pubkey < "$RELAY_DIR/relay_privatekey")"

echo "[5/8] Configuring host wg0..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
PRIVKEY="$(tr -d '\r\n' < "$RELAY_DIR/relay_privatekey")"
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/16
ListenPort = 51820
PrivateKey = ${PRIVKEY}
SaveConfig = false
EOF
chmod 600 /etc/wireguard/wg0.conf

sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

wg-quick down wg0 >/dev/null 2>&1 || true
wg-quick up wg0
systemctl enable wg-quick@wg0

echo "[6/8] Registering relay with control plane..."
json_payload="{\"hostname\":\"${RELAY_HOSTNAME}\",\"public_ip\":\"${PUBLIC_IP}\",\"endpoint_host\":\"${RELAY_ENDPOINT_HOST}\",\"public_key\":\"${RELAY_PUBLIC_KEY}\"}"

curl -fsSL -X POST "${BRAIN_URL%/}/infra/relay-register" \
  -H "Content-Type: application/json" \
  -H "x-relay-key: ${RELAY_SERVICE_KEY}" \
  -d "$json_payload" >/dev/null

echo "[7/8] Starting relay service..."
cd "$RELAY_DIR"
# Warm base image pull to avoid metadata stalls on some VPS networks
docker pull python:3.11-slim || true
# Force classic builder path for maximum compatibility
DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker compose -f docker-compose.relay.yml up -d --build

echo "[8/8] Done."
echo "Relay hostname: $RELAY_HOSTNAME"
echo "Relay public IP: $PUBLIC_IP"
echo "Relay public key: $RELAY_PUBLIC_KEY"
echo "Control plane: $BRAIN_URL"
echo ""
echo "Make sure provider firewall allows: UDP 51820"
