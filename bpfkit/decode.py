"""Decode packets into plain dicts and render tcpdump-like one-line summaries.

Only the standard library is used. The decoder records the byte offsets it used
so that pattern mining (bpfgen) can emit filters whose semantics match the
filter engine (bpf.py) exactly - e.g. it notes whether an IPv6 transport header
directly follows the fixed header, which is what libpcap's `port` checks.
"""

import ipaddress
import struct
import time

TCP_FLAG_LETTERS = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                    (0x10, "."), (0x20, "U"), (0x40, "E"), (0x80, "W")]

ICMP_TYPES = {0: "echo reply", 3: "unreachable", 4: "source quench",
              5: "redirect", 8: "echo request", 11: "time exceeded",
              12: "parameter problem", 13: "timestamp", 14: "timestamp reply"}
ICMP6_TYPES = {1: "unreachable", 2: "packet too big", 3: "time exceeded",
               4: "parameter problem", 128: "echo request", 129: "echo reply",
               133: "router solicitation", 134: "router advertisement",
               135: "neighbor solicitation", 136: "neighbor advertisement",
               137: "redirect", 143: "MLDv2 report"}
IP_PROTO_LABEL = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE",
                  50: "ESP", 51: "AH", 58: "ICMP6", 89: "OSPF", 103: "PIM",
                  112: "VRRP", 132: "SCTP"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
MODBUS_FUNCS = {1: "read coils", 2: "read discrete inputs", 3: "read holding registers",
                4: "read input registers", 5: "write single coil",
                6: "write single register", 15: "write multiple coils",
                16: "write multiple registers", 23: "read/write multiple registers",
                43: "encapsulated interface"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"HTTP/1.")
IPV6_EXT = (0, 43, 44, 60)


def _need(b, n):
    if len(b) != n:
        raise IndexError("truncated field")  # caught by decode(): marks the packet truncated
    return b


def mac_str(b):
    return ":".join("%02x" % x for x in bytearray(_need(b, 6)))


def ip4_str(b):
    return "%d.%d.%d.%d" % tuple(bytearray(_need(b, 4)))


def ip6_str(b):
    return str(ipaddress.IPv6Address(bytes(_need(b, 16))))


def decode(pkt):
    """Return a dict describing the packet. Never raises on malformed data."""
    d = {"index": pkt.index, "len": pkt.wirelen, "caplen": pkt.caplen,
         "linktype": pkt.linktype, "vlans": [], "l3": None, "l4": None}
    data = pkt.data
    try:
        _decode_link(d, data, pkt.linktype)
    except (struct.error, IndexError, ValueError):
        d["truncated"] = True
    return d


def _decode_link(d, data, lt):
    if lt == 1:
        d["eth_dst"], d["eth_src"] = mac_str(data[0:6]), mac_str(data[6:12])  # both or neither
        et = struct.unpack(">H", data[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100):
            tci = struct.unpack(">H", data[off:off + 2])[0]
            d["vlans"].append(tci & 0x0FFF)
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
    elif lt == 113:
        et = struct.unpack(">H", data[14:16])[0]
        d["sll_pkttype"] = struct.unpack(">H", data[0:2])[0]
        off = 16
    elif lt == 276:
        et = struct.unpack(">H", data[0:2])[0]
        off = 20
    elif lt in (0, 108):
        af = struct.unpack(">I", data[0:4])[0]
        if lt == 0 and struct.unpack("<I", data[0:4])[0] < 256:
            af = struct.unpack("<I", data[0:4])[0]
        et = 0x0800 if af == 2 else 0x86DD if af in (10, 24, 28, 30) else -1
        off = 4
    elif lt in (101, 228, 229):
        v = data[0] >> 4
        et = 0x0800 if v == 4 else 0x86DD if v == 6 else -1
        off = 0
    else:
        d["unsupported_link"] = True
        return
    d["ethertype"] = et
    d["nl_off"] = off
    if et == 0x0800:
        _decode_ip4(d, data, off)
    elif et == 0x86DD:
        _decode_ip6(d, data, off)
    elif et in (0x0806, 0x8035):
        _decode_arp(d, data, off)


# Each decoder reads all fixed fields into locals first and sets "l3" only
# together with them, so "l3 present" always implies its core fields exist
# (truncated packets just stop at the last complete layer).

def _decode_ip4(d, data, off):
    vihl = data[off]
    tot, ident, frag = struct.unpack(">HHH", data[off + 2:off + 8])
    ttl, proto = data[off + 8], data[off + 9]
    src, dst = ip4_str(data[off + 12:off + 16]), ip4_str(data[off + 16:off + 20])
    d.update(l3="ipv4", ihl=(vihl & 0x0F) * 4, ip_id=ident, ttl=ttl, proto=proto, src=src, dst=dst,
             frag_off=frag & 0x1FFF, mf=bool(frag & 0x2000), df=bool(frag & 0x4000))
    if d["frag_off"]:
        return  # non-first fragment: no transport header
    _decode_l4(d, data, off + d["ihl"], proto, ip_end=off + tot)


def _decode_ip6(d, data, off):
    plen = struct.unpack(">H", data[off + 4:off + 6])[0]
    nh, hlim = data[off + 6], data[off + 7]
    src, dst = ip6_str(data[off + 8:off + 24]), ip6_str(data[off + 24:off + 40])
    d.update(l3="ipv6", hlim=hlim, ttl=hlim, src=src, dst=dst, ip6_nh=nh, proto=nh,
             ip6_direct=nh not in IPV6_EXT)  # ip6_direct: what libpcap's port/tcp[] logic sees
    p = off + 40
    hops = 0
    while nh in IPV6_EXT and hops < 8:
        if nh == 44:
            if hops == 0:
                d["ip6_frag_nh"] = data[p]  # what libpcap's 'ip6 proto' also checks
            fo = struct.unpack(">H", data[p + 2:p + 4])[0]
            d["frag_off"] = fo >> 3
            d["mf"] = bool(fo & 1)
            nh = data[p]
            p += 8
            if d["frag_off"]:
                d["proto"] = nh
                return
        else:
            nxt, hlen = data[p], (data[p + 1] + 1) * 8
            nh = nxt
            p += hlen
        hops += 1
    d["proto"] = nh
    _decode_l4(d, data, p, nh, ip_end=off + 40 + plen)


def _decode_arp(d, data, off):
    hlen, plen = data[off + 4], data[off + 5]
    op = struct.unpack(">H", data[off + 6:off + 8])[0]
    d.update(l3="arp", arp_op=op)
    if hlen == 6 and plen == 4:
        sha, spa = mac_str(data[off + 8:off + 14]), ip4_str(data[off + 14:off + 18])
        tha, tpa = mac_str(data[off + 18:off + 24]), ip4_str(data[off + 24:off + 28])
        d.update(arp_sha=sha, src=spa, arp_tha=tha, dst=tpa)


def _decode_l4(d, data, off, proto, ip_end):
    end = min(len(data), ip_end) if ip_end > off else len(data)
    d["l4_off"] = off
    # Ports are decoded on their own first, because the filter engine only
    # needs those 4 bytes for 'port N'. "l4" is set only once its fields exist.
    if proto in (6, 17, 132):
        sp, dp = struct.unpack(">HH", data[off:off + 4])
        d.update(l4={6: "tcp", 17: "udp", 132: "sctp"}[proto], sport=sp, dport=dp)
    if proto == 6:
        seq, ack, offflags, win = struct.unpack(">IIHH", data[off + 4:off + 16])
        doff = (offflags >> 12) * 4
        d.update(seq=seq, ack=ack, flags=offflags & 0xFF, win=win, tcp_hlen=doff)
        d["payload_off"] = off + doff
        d["payload"] = bytes(data[off + doff:end])
    elif proto == 17:
        d["payload_off"] = off + 8
        d["payload"] = bytes(data[off + 8:end])
    elif proto in (1, 58):
        t, c = data[off], data[off + 1]
        d.update(l4="icmp" if proto == 1 else "icmp6", icmp_type=t, icmp_code=c)
        d["payload_off"] = off + 8
        d["payload"] = bytes(data[off + 8:end])
    elif proto != 132:
        d["l4"] = IP_PROTO_LABEL.get(proto, "proto-%d" % proto).lower()
        d["payload_off"] = off
        d["payload"] = bytes(data[off:end])
    _decode_app(d)


# --------------------------------------------------------------------------
# Light application-layer hints (DNS, HTTP, TLS SNI)
# --------------------------------------------------------------------------

def _decode_app(d):
    pl = d.get("payload") or b""
    ports = (d.get("sport"), d.get("dport"))
    if d["l4"] == "udp" and (53 in ports or 5353 in ports) and len(pl) >= 12:
        _dns(d, pl)
    elif d["l4"] == "tcp" and pl:
        if 502 in ports and len(pl) >= 8 and pl[2:4] == b"\x00\x00":
            fc = pl[7]
            d["modbus_func"] = fc
            d["modbus"] = "Modbus unit %d func %d (%s)" % (
                pl[6], fc, MODBUS_FUNCS.get(fc & 0x7F, "?") + (" EXCEPTION" if fc & 0x80 else ""))
        elif pl.startswith(HTTP_METHODS):
            line = pl.split(b"\r\n", 1)[0][:120]
            d["http"] = line.decode("latin-1")
            for hl in pl.split(b"\r\n")[1:20]:
                if hl.lower().startswith(b"host:"):
                    d["http_host"] = hl[5:].strip().decode("latin-1")
        elif len(pl) > 5 and pl[0] == 0x16 and pl[1] == 0x03:
            d["tls"] = "handshake"
            if len(pl) > 5 and pl[5] == 1:
                d["tls"] = "ClientHello"
                sni = _tls_sni(pl)
                if sni:
                    d["tls_sni"] = sni
            elif len(pl) > 5 and pl[5] == 2:
                d["tls"] = "ServerHello"


def _dns(d, pl):
    try:
        ident, flags, qd = struct.unpack(">HHH", pl[:6])
        d["dns_id"] = ident
        d["dns_qr"] = "response" if flags & 0x8000 else "query"
        d["dns_rcode"] = flags & 0x0F
        if qd:
            labels, p = [], 12
            while p < len(pl) and pl[p] and len(labels) < 64:
                n = pl[p]
                if n & 0xC0:
                    break
                labels.append(pl[p + 1:p + 1 + n].decode("latin-1"))
                p += 1 + n
            qtype = struct.unpack(">H", pl[p + 1:p + 3])[0] if p + 3 <= len(pl) else 0
            d["dns_qname"] = ".".join(labels)
            d["dns_qtype"] = DNS_TYPES.get(qtype, str(qtype))
    except (struct.error, IndexError):
        pass


def _tls_sni(pl):
    try:
        p = 5 + 4 + 2 + 32  # record hdr, handshake hdr, version, random
        p += 1 + pl[p]  # session id
        p += 2 + struct.unpack(">H", pl[p:p + 2])[0]  # cipher suites
        p += 1 + pl[p]  # compression
        end = p + 2 + struct.unpack(">H", pl[p:p + 2])[0]
        p += 2
        while p + 4 <= min(end, len(pl)):
            et, el = struct.unpack(">HH", pl[p:p + 4])
            if et == 0:
                n = struct.unpack(">H", pl[p + 7:p + 9])[0]
                return pl[p + 9:p + 9 + n].decode("latin-1")
            p += 4 + el
    except (struct.error, IndexError):
        pass
    return None


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def flags_str(f):
    s = "".join(ch for bit, ch in TCP_FLAG_LETTERS if f & bit)
    return s or "none"


def fmt_ts(pkt, absolute=False):
    sec, usec = pkt.ts_micro()
    if absolute:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec)) + ".%06d" % usec
    return time.strftime("%H:%M:%S", time.gmtime(sec)) + ".%06d" % usec


def endpoint(d, which):
    addr = d.get(which)
    port = d.get("sport" if which == "src" else "dport")
    if addr is None:
        return "?"
    if port is None:
        return addr
    return ("[%s]:%d" if ":" in addr else "%s.%d") % (addr, port)


def summary(d):
    """tcpdump-like one-line description of a decoded packet."""
    try:
        return _summary(d)
    except (KeyError, TypeError):  # partially decoded (truncated/malformed) packet
        known = " ".join("%s=%s" % (k, d[k]) for k in ("l3", "src", "dst", "l4", "sport", "dport") if d.get(k) is not None)
        return "truncated/malformed packet (%s), length %d" % (known or "nothing decoded", d["len"])


def _summary(d):
    vl = "".join("vlan %d, " % v for v in d["vlans"])
    l3 = d.get("l3")
    if d.get("unsupported_link"):
        return "link type %d (not decoded), length %d" % (d["linktype"], d["len"])
    if l3 == "arp":
        op = d.get("arp_op")
        if op == 1:
            return "%sARP, Request who-has %s tell %s, length %d" % (vl, d.get("dst"), d.get("src"), d["len"])
        if op == 2:
            return "%sARP, Reply %s is-at %s, length %d" % (vl, d.get("src"), d.get("arp_sha"), d["len"])
        return "%sARP op %s, length %d" % (vl, op, d["len"])
    if l3 not in ("ipv4", "ipv6"):
        et = d.get("ethertype")
        base = "ethertype 0x%04x" % et if isinstance(et, int) and et >= 0 else "unknown"
        if "eth_src" in d:
            base = "%s > %s, %s" % (d["eth_src"], d["eth_dst"], base)
        return "%s%s, length %d" % (vl, base, d["len"])
    ipv = "IP" if l3 == "ipv4" else "IP6"
    l4 = d.get("l4")
    src, dst = endpoint(d, "src"), endpoint(d, "dst")
    if d.get("frag_off"):
        return "%s%s %s > %s: fragment (offset %d, proto %s), length %d" % (
            vl, ipv, d["src"], d["dst"], d["frag_off"] * 8,
            IP_PROTO_LABEL.get(d.get("proto"), d.get("proto")), d["len"])
    if l4 == "tcp":
        extra = "Flags [%s], seq %d" % (flags_str(d["flags"]), d["seq"])
        if d["flags"] & 0x10:
            extra += ", ack %d" % d["ack"]
        extra += ", win %d, length %d" % (d["win"], len(d.get("payload", b"")))
        app = d.get("http") or d.get("modbus") or (("TLS %s" % d["tls"]) + (" SNI=%s" % d["tls_sni"] if d.get("tls_sni") else "") if d.get("tls") else None)
        if app:
            extra += ": " + app
        return "%s%s %s > %s: %s" % (vl, ipv, src, dst, extra)
    if l4 == "udp":
        if "dns_qr" in d:
            q = d.get("dns_qname")
            extra = "DNS %s %s %s? %s" % (d["dns_qr"], d["dns_id"], d.get("dns_qtype", ""), q or "")
            if d["dns_qr"] == "response" and d.get("dns_rcode"):
                extra += " rcode=%d" % d["dns_rcode"]
        else:
            extra = "UDP, length %d" % len(d.get("payload", b""))
        return "%s%s %s > %s: %s" % (vl, ipv, src, dst, extra)
    if l4 in ("icmp", "icmp6"):
        names = ICMP_TYPES if l4 == "icmp" else ICMP6_TYPES
        t = d["icmp_type"]
        return "%s%s %s > %s: %s %s (type %d code %d), length %d" % (
            vl, ipv, src, dst, l4.upper(), names.get(t, "type %d" % t), t, d["icmp_code"], d["len"])
    return "%s%s %s > %s: %s, length %d" % (vl, ipv, src, dst, (l4 or "?").upper(), d["len"])


def verbose_lines(d):
    """Multi-line field dump for -v output."""
    keys = ["linktype", "len", "caplen", "eth_src", "eth_dst", "vlans", "ethertype",
            "l3", "src", "dst", "ttl", "proto", "ip_id", "df", "mf", "frag_off",
            "ihl", "ip6_nh", "ip6_direct", "l4", "sport", "dport", "flags", "seq",
            "ack", "win", "tcp_hlen", "icmp_type", "icmp_code", "dns_qr",
            "dns_qname", "dns_qtype", "http", "http_host", "tls", "tls_sni", "modbus",
            "nl_off", "l4_off", "payload_off", "truncated"]
    out = []
    for k in keys:
        if k in d and d[k] not in (None, []):
            v = d[k]
            if k == "ethertype" and isinstance(v, int) and v >= 0:
                v = "0x%04x" % v
            elif k == "flags":
                v = "0x%02x [%s]" % (v, flags_str(v))
            out.append("    %-12s %s" % (k, v))
    pl = d.get("payload")
    if pl:
        out.append("    %-12s %d bytes: %s" % ("payload", len(pl), printable(pl[:64])))
    return out


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in bytearray(b))


def hexdump(data, indent="    "):
    lines = []
    for i in range(0, len(data), 16):
        chunk = bytearray(data[i:i + 16])
        hx = " ".join("%02x" % c for c in chunk)
        lines.append("%s0x%04x:  %-47s  %s" % (indent, i, hx, printable(chunk)))
    return lines


def to_jsonable(d):
    out = {}
    for k, v in d.items():
        if isinstance(v, bytes):
            out[k] = v[:256].hex()
        else:
            out[k] = v
    return out
