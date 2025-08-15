#!/usr/bin/env sh
set -eu
: "${SINK_IPV4:=}"
: "${SINK_IPV6:=}"
: "${DNS_TTL:=30}"
: "${LOG_LEVEL:=INFO}"
if [ -z "$SINK_IPV4$SINK_IPV6" ]; then
  echo "[ERROR] Set SINK_IPV4 and/or SINK_IPV6 to your server's public IP" >&2
  exit 2
fi
exec python3 /app/dns_sink.py
