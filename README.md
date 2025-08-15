# Full DNS → Proxy Solution (DNS sinkhole + HAProxy SNI/HTTP)

This setup lets you **point client DNS to your server** and have web traffic
(HTTP/HTTPS) transparently routed through your box — without terminating TLS.

## What’s included
- **dns-sink** (port 53/udp): answers every A/AAAA query with your server IP.
- **sni-proxy** (ports 80/tcp & 443/tcp): routes HTTP by Host header and TLS by SNI
  to the correct origin. TLS is end-to-end with the origin (no cert issues).

> Not a full VPN: raw IP connections, non-HTTP(S) protocols, and DoH/DoT are not captured.
> HTTP/3 (QUIC/UDP/443) is not proxied; clients will fall back to TCP/443.

## Prereqs
- Linux host with Docker/Compose.
- Ports **53/udp**, **80/tcp**, **443/tcp** free on the host.
- Outbound TCP/80 and TCP/443 allowed from the host.

## Quick start
1. **Edit** `docker-compose.yml` and set:
   ```yaml
   SINK_IPV4: "YOUR.PUBLIC.IPv4"
   # SINK_IPV6: "YOUR:PUBLIC:IPv6"  # optional
   ```
2. If your host is running a local DNS stub (e.g. systemd-resolved) that binds 127.0.0.53,
   disable the stub so port 53 is free:
   ```bash
   sudo sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
   sudo systemctl restart systemd-resolved
   echo -e 'nameserver 1.1.1.1\nnameserver 9.9.9.9' | sudo tee /etc/resolv.conf
   ```
3. **Launch**:
   ```bash
   docker compose up -d
   docker compose logs -f
   ```
4. **Point a client’s DNS** to your server’s IP (e.g. on the device or router).

## Optional: make TCP fallback faster
Many browsers try QUIC (UDP/443) first. To push them to TCP quickly, block UDP/443
on the edge firewall (on your host or upstream). Example (iptables):
```bash
sudo iptables -A INPUT -p udp --dport 443 -j REJECT
```
(Adjust for your firewall system; revert with `-D` to remove.)

## Troubleshooting
- **Port already in use**: free 53/udp, 80/tcp, 443/tcp before starting, or stop the conflicting service.
- **Client can’t browse**:
  - Check logs: `docker compose logs -f` (look for `set-dst` errors or DNS issues).
  - Ensure the client is *not* using DoH/DoT (these bypass your DNS). Disable or block DoH if needed.
  - Make sure outbound 80/443 from host is allowed.
  - If IPv6 egress is broken, don’t set `SINK_IPV6`; v4 will still work.
- **IP-only HTTPS**: connecting to `https://<ip>` won’t work (no SNI/Host to route).

## Files
- `docker-compose.yml` — brings up both services (host networking for simplicity/perf)
- `haproxy.cfg` — HAProxy config
- `dns-sink/` — minimal DNS sinkhole server
