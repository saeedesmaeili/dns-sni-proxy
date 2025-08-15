#!/usr/bin/env python3
# Minimal DNS sinkhole: answers every A/AAAA with SINK_IPV4/6
import asyncio, os, ipaddress, logging, sys
from typing import Tuple
from dnslib import DNSRecord, RR, A, AAAA, QTYPE, RCODE

SINK_IPV4 = os.getenv("SINK_IPV4", "")
SINK_IPV6 = os.getenv("SINK_IPV6", "")
DNS_HOST  = os.getenv("DNS_HOST", "0.0.0.0")
DNS_PORT  = int(os.getenv("DNS_PORT", "53"))
DNS_TTL   = int(os.getenv("DNS_TTL", "30"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

def _valid_ip(ip, v):
    try:
        if not ip: return False
        ipaddress.ip_address(ip)
        return (v==4 and ":" not in ip) or (v==6 and ":" in ip)
    except Exception:
        return False

class DNSProto(asyncio.DatagramProtocol):
    def __init__(self, v4, v6):
        self.v4 = v4 if _valid_ip(v4,4) else None
        self.v6 = v6 if _valid_ip(v6,6) else None

    def connection_made(self, transport):
        self.t = transport
        logging.info(f"DNS sinkhole listening on {transport.get_extra_info('socket').getsockname()}")

    def datagram_received(self, data: bytes, addr: Tuple[str,int]):
        try:
            req = DNSRecord.parse(data)
        except Exception as e:
            logging.debug(f"parse error from {addr}: {e}")
            return
        try:
            rep = req.reply()
            for q in req.questions:
                if q.qtype == QTYPE.A and self.v4:
                    rep.add_answer(RR(q.qname, QTYPE.A, rdata=A(self.v4), ttl=DNS_TTL))
                elif q.qtype == QTYPE.AAAA and self.v6:
                    rep.add_answer(RR(q.qname, QTYPE.AAAA, rdata=AAAA(self.v6), ttl=DNS_TTL))
                else:
                    # NODATA for other types; keeps NOERROR
                    pass
            self.t.sendto(rep.pack(), addr)
        except Exception as e:
            try:
                sf = req.reply(); sf.header.rcode = RCODE.SERVFAIL
                self.t.sendto(sf.pack(), addr)
            except Exception:
                pass
            logging.error(f"reply error: {e}")

async def main():
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format='[%(levelname)s] %(message)s')
    if not _valid_ip(SINK_IPV4,4) and not _valid_ip(SINK_IPV6,6):
        logging.error("Set SINK_IPV4 and/or SINK_IPV6 to valid addresses."); sys.exit(1)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: DNSProto(SINK_IPV4, SINK_IPV6), local_addr=(DNS_HOST, DNS_PORT))
    try:
        await asyncio.sleep(10**9)
    finally:
        transport.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
