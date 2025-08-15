# The error came from Docker not supporting heredoc in HEALTHCHECK on your builder,
# so the line starting with `import` was parsed as a Dockerfile instruction.
# Fix: use a one‑liner healthcheck (no heredoc).

# --- Dockerfile (fixed) ---
# syntax=docker/dockerfile:1
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN groupadd -g 10001 app && useradd -m -u 10001 -g 10001 app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && PYBIN=$(command -v python3) \
 && setcap 'cap_net_bind_service=+ep' "$PYBIN"

COPY dns_sni_proxy.py ./
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

USER app

EXPOSE 53/udp 80 443

# Simple healthcheck without heredoc (works on older Docker versions)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b'\\x00'*12, ('127.0.0.1',53)); sys.exit(0)" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]

# docker-compose.yml is unchanged; rebuild with:
#   docker compose up --build -d