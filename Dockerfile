# syntax=docker/dockerfile:1
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY dns_sni_proxy.py ./
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# NOTE: run as root so we can bind :53/:80/:443 without setcap
# USER root

EXPOSE 53/udp 80 443

# Simple healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b'\\x00'*12, ('127.0.0.1',53)); sys.exit(0)" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]