#!/usr/bin/env sh
set -eu
: "${SINK_IPV4:=}"
: "${SINK_IPV6:=}"
: "${DNS_UPSTREAM:=1.1.1.1}"
: "${ALLOWLIST:=}"
: "${DNS_HOST:=0.0.0.0}"
: "${DNS_PORT:=53}"
: "${HTTP_HOST:=0.0.0.0}"
: "${HTTP_PORT:=80}"
: "${TLS_HOST:=0.0.0.0}"
: "${TLS_PORT:=443}"
: "${DNS_TTL:=30}"
: "${DNS_TIMEOUT:=2.5}"
: "${LOG_LEVEL:=INFO}"
if [ -z "$SINK_IPV4$SINK_IPV6" ]; then
  echo "[ERROR] You must set SINK_IPV4 and/or SINK_IPV6 to the public IP of this host" >&2
  exit 2
fi
exec python3 /app/dns_sni_proxy.py