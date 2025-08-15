#!/usr/bin/env python3
"""
DNS + SNI/HTTP Transparent Proxy ("DNS-based pseudo‑VPN")
=========================================================

⚠️ What this actually does (and its limits)
-------------------------------------------
- Acts as a DNS server that answers every A/AAAA query with your proxy IP.
- Transparent HTTP proxy (reads Host header) and TLS SNI proxy (forwards based on SNI without TLS termination).
- Not a full VPN: won’t handle raw IP, non-HTTP(S) protocols, or clients using DoH/DoT.

Quick start
-----------
1) pip install dnslib
2) export SINK_IPV4=... (and optionally SINK_IPV6)
3) sudo -E python3 dns_sni_proxy.py

License: MIT
"""

import asyncio
import ipaddress
import logging
import os
import socket
import struct
import sys
from typing import Optional, Tuple

from dnslib import DNSRecord, RR, A, AAAA, QTYPE, RCODE

SINK_IPV4 = os.getenv("SINK_IPV4", "")
SINK_IPV6 = os.getenv("SINK_IPV6", "")
DNS_UPSTREAM = os.getenv("DNS_UPSTREAM", "1.1.1.1")
ALLOWLIST = [d.strip().lower() for d in os.getenv("ALLOWLIST", "").split(",") if d.strip()]

DNS_HOST = os.getenv("DNS_HOST", "0.0.0.0")
DNS_PORT = int(os.getenv("DNS_PORT", "53"))
HTTP_HOST = os.getenv("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
TLS_HOST = os.getenv("TLS_HOST", "0.0.0.0")
TLS_PORT = int(os.getenv("TLS_PORT", "443"))

DNS_TTL = int(os.getenv("DNS_TTL", "30"))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "2.5"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


def _valid_ip(ip: str, version: int) -> bool:
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return (version == 4 and ":" not in ip) or (version == 6 and ":" in ip)
    except ValueError:
        return False


def domain_in_allowlist(qname: str) -> bool:
    return True
    qname = qname.rstrip('.').lower()
    for suffix in ALLOWLIST:
        if qname == suffix or qname.endswith("." + suffix):
            return True
    return False


class DNSDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, sink_ipv4: str, sink_ipv6: str):
        super().__init__()
        self.sink_ipv4 = sink_ipv4 if _valid_ip(sink_ipv4, 4) else None
        self.sink_ipv6 = sink_ipv6 if _valid_ip(sink_ipv6, 6) else None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        logging.info(f"DNS listening on {sock.getsockname()}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            logging.debug(f"DNS parse error from {addr}: {e}")
            return

        try:
            if any(domain_in_allowlist(str(q.qname)) for q in request.questions):
                resp = self.forward_upstream(data)
                if resp:
                    self.transport.sendto(resp, addr)
                return
        except Exception as e:
            logging.warning(f"DNS upstream forward failed, falling back to sink: {e}")

        try:
            reply = request.reply()
            for q in request.questions:
                qname = q.qname
                if q.qtype == QTYPE.A and self.sink_ipv4:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.sink_ipv4), ttl=DNS_TTL))
                elif q.qtype == QTYPE.AAAA and self.sink_ipv6:
                    reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(self.sink_ipv6), ttl=DNS_TTL))
            packet = reply.pack()
            self.transport.sendto(packet, addr)
        except Exception as e:
            try:
                servfail = request.reply()
                servfail.header.rcode = RCODE.SERVFAIL
                self.transport.sendto(servfail.pack(), addr)
            except Exception:
                pass
            logging.error(f"DNS reply error: {e}")

    def forward_upstream(self, packet: bytes) -> Optional[bytes]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(DNS_TIMEOUT)
            s.sendto(packet, (DNS_UPSTREAM, 53))
            return s.recv(4096)


class HTTPTransparentProxy:
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info('peername')
        try:
            head = await self._read_until_double_crlf(reader, max_bytes=65536)
            if not head:
                writer.close(); await writer.wait_closed(); return
            host, port = self._extract_host_port(head)
            if not host:
                writer.close(); await writer.wait_closed(); return
            port = port or 80
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
            upstream_writer.write(head); await upstream_writer.drain()
            await asyncio.gather(self._pipe(reader, upstream_writer), self._pipe(upstream_reader, writer))
        except Exception as e:
            logging.debug(f"HTTP error with {peer}: {e}")
        finally:
            with contextlib_silent():
                writer.close(); await writer.wait_closed()

    async def _read_until_double_crlf(self, reader: asyncio.StreamReader, max_bytes=65536) -> bytes:
        buf = bytearray()
        while True:
            chunk = await reader.read(2048)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf or len(buf) > max_bytes:
                break
        return bytes(buf)

    def _extract_host_port(self, head: bytes) -> Tuple[Optional[str], Optional[int]]:
        try:
            header_text = head.decode('iso-8859-1', errors='ignore')
            host_line = None
            for line in header_text.split("\r\n"):
                if line.lower().startswith("host:"):
                    host_line = line.split(":", 1)[1].strip()
                    break
            if not host_line:
                return None, None
            if ":" in host_line and not host_line.endswith(']'):
                host, port_s = host_line.rsplit(":", 1)
                try:
                    return host.strip(), int(port_s)
                except ValueError:
                    return host.strip(), None
            return host_line.strip(), None
        except Exception:
            return None, None

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data); await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib_silent():
                writer.close(); await writer.wait_closed()


class TLSSNIProxy:
    def __init__(self, default_port: int = 443):
        self.default_port = default_port

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        peer = client_writer.get_extra_info('peername')
        try:
            hello = await self._read_client_hello(client_reader)
            if not hello:
                return await self._close(client_writer)
            sni_host = self._parse_sni(hello)
            if not sni_host:
                return await self._close(client_writer)
            upstream_reader, upstream_writer = await asyncio.open_connection(sni_host, self.default_port)
            upstream_writer.write(hello); await upstream_writer.drain()
            await asyncio.gather(self._pipe(client_reader, upstream_writer), self._pipe(upstream_reader, client_writer))
        except Exception as e:
            logging.debug(f"TLS error with {peer}: {e}")
        finally:
            await self._close(client_writer)

    async def _read_client_hello(self, reader: asyncio.StreamReader, cap: int = 65536) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < cap:
            need = 5 - (len(buf) if len(buf) < 5 else 5)
            if need > 0:
                chunk = await reader.read(need)
                if not chunk:
                    break
                buf += chunk
                if len(buf) < 5:
                    continue
            if buf[0] != 0x16:
                return bytes(buf)
            rec_len = struct.unpack('!H', buf[3:5])[0]
            total = 5 + rec_len
            while len(buf) < total:
                chunk = await reader.read(total - len(buf))
                if not chunk:
                    break
                buf += chunk
            sni = self._parse_sni(bytes(buf))
            if sni:
                return bytes(buf)
            more = await reader.read(2048)
            if not more:
                break
            buf += more
        return bytes(buf) if buf else None

    def _parse_sni(self, data: bytes) -> Optional[str]:
        try:
            if len(data) < 5 or data[0] != 0x16:
                return None
            idx = 5
            if len(data) < idx + 4:
                return None
            if data[idx] != 0x01:
                return None
            idx += 4
            idx += 2 + 32
            if len(data) < idx + 1:
                return None
            sid_len = data[idx]
            idx += 1 + sid_len
            if len(data) < idx + 2:
                return None
            cs_len = struct.unpack('!H', data[idx:idx+2])[0]
            idx += 2 + cs_len
            if len(data) < idx + 1:
                return None
            cm_len = data[idx]
            idx += 1 + cm_len
            if len(data) < idx + 2:
                return None
            ext_total_len = struct.unpack('!H', data[idx:idx+2])[0]
            idx += 2
            end = idx + ext_total_len
            while idx + 4 <= end and idx + 4 <= len(data):
                ext_type = struct.unpack('!H', data[idx:idx+2])[0]
                ext_len = struct.unpack('!H', data[idx+2:idx+4])[0]
                idx += 4
                if ext_type == 0:
                    if idx + 2 > len(data):
                        return None
                    list_len = struct.unpack('!H', data[idx:idx+2])[0]
                    j = idx + 2
                    while j + 3 <= idx + 2 + list_len and j + 3 <= len(data):
                        name_type = data[j]
                        name_len = struct.unpack('!H', data[j+1:j+3])[0]
                        j += 3
                        if name_type == 0 and j + name_len <= len(data):
                            host = data[j:j+name_len].decode('idna', 'ignore')
                            return host.rstrip('.')
                        j += name_len
                    return None
                idx += ext_len
        except Exception:
            return None
        return None

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data); await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib_silent():
                writer.close(); await writer.wait_closed()

    async def _close(self, w: asyncio.StreamWriter):
        with contextlib_silent():
            w.close(); await w.wait_closed()

from contextlib import contextmanager

@contextmanager
def contextlib_silent():
    try:
        yield
    except Exception:
        pass

async def main():
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format='[%(levelname)s] %(message)s')
    if not _valid_ip(SINK_IPV4, 4) and not _valid_ip(SINK_IPV6, 6):
        logging.error("You must set SINK_IPV4 and/or SINK_IPV6 to valid addresses.")
        sys.exit(1)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: DNSDatagramProtocol(SINK_IPV4, SINK_IPV6), local_addr=(DNS_HOST, DNS_PORT))
    http_proxy = HTTPTransparentProxy()
    http_server = await asyncio.start_server(http_proxy.handle, HTTP_HOST, HTTP_PORT, reuse_port=True)
    logging.info(f"HTTP proxy listening on {[s.getsockname() for s in http_server.sockets]}")
    tls_proxy = TLSSNIProxy(default_port=TLS_PORT)
    tls_server = await asyncio.start_server(tls_proxy.handle, TLS_HOST, TLS_PORT, reuse_port=True)
    logging.info(f"TLS SNI proxy listening on {[s.getsockname() for s in tls_server.sockets]}")
    try:
        await asyncio.gather(http_server.serve_forever(), tls_server.serve_forever())
    finally:
        transport.close(); http_server.close(); tls_server.close()
        await http_server.wait_closed(); await tls_server.wait_closed()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass