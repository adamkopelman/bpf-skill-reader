"""A pure-Python implementation of the libpcap/tcpdump filter language.

The goal is to behave like `tcpdump -r file 'expr'` without needing libpcap,
tcpdump or any third-party package, so it works on an air-gapped host that only
has a Python 3 interpreter.

Semantics deliberately copied from libpcap (see knowledge/bpf/04-gotchas.md):
  * `and` and `or` have EQUAL precedence and associate left to right;
    `not` binds tightest.
  * Bare values inherit the previous primitive's qualifiers:
    `port 80 or 443` == `port 80 or port 443`.
  * Every `vlan` keyword shifts the offsets of every primitive that follows it
    in the expression text by 4 bytes (compile-time, like libpcap on files).
  * `tcp[]`, `udp[]`, `icmp[]` ... only index into IPv4 packets (first
    fragment only). `port`/`host`/`tcp`/`udp` do work for IPv6, but IPv6
    extension headers are not walked (except a Fragment header for `ip6 proto`).
  * An out-of-bounds load anywhere makes the whole filter reject the packet,
    exactly like a classic BPF program.
  * A relation that indexes a protocol (`ip[9] = 6`) is false for packets that
    are not of that protocol, so `not ip[9] = 6` is true for ARP.

Supported link types: Ethernet, Linux cooked (SLL/SLL2), raw IP, BSD NULL/LOOP.

Usage:
    from bpfkit.bpf import compile_filter
    flt = compile_filter("tcp port 443 and host 10.0.0.1")
    flt.match(packet)   # packet has .data, .wirelen, .linktype
"""

import ipaddress
import re
import socket
import struct

__all__ = ["compile_filter", "FilterSyntaxError", "FilterUnsupported", "BPFFilter"]


class FilterSyntaxError(Exception):
    pass


class FilterUnsupported(Exception):
    pass


class _FatalSyntaxError(FilterSyntaxError):
    """A definite error inside a relation; the parser must not backtrack past it."""


class _Reject(Exception):
    """Out-of-bounds load / divide by zero: the whole program returns 0."""


class _NoProto(Exception):
    """A protocol-indexed load on a packet of another protocol."""


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

ETH_IP, ETH_IP6, ETH_ARP, ETH_RARP = 0x0800, 0x86DD, 0x0806, 0x8035
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

# Exactly the names libpcap accepts after 'ether proto \' (verified on 1.5.3 to
# 1.10.4). Anything else, such as \vlan, \lldp or \mpls, is an error there too.
ETHER_PROTO_NAMES = {
    "ip": ETH_IP, "ip6": ETH_IP6, "arp": ETH_ARP, "rarp": ETH_RARP,
    "decnet": 0x6003, "lat": 0x6004, "sca": 0x6007, "moprc": 0x6002,
    "mopdl": 0x6001, "loopback": 0x9000,
}

# Names libpcap resolves after 'ip proto \' via /etc/protocols on a standard
# Linux host. igrp, ip6, icmp6 and carp are NOT among them (tcpdump rejects
# them), so they are left out to keep filters portable.
IP_PROTO_NAMES = {
    "icmp": 1, "igmp": 2, "ggp": 3, "ipip": 4, "tcp": 6, "egp": 8,
    "udp": 17, "rsvp": 46, "gre": 47, "esp": 50, "ah": 51,
    "eigrp": 88, "ospf": 89, "pim": 103, "vrrp": 112, "l2tp": 115, "sctp": 132,
}
# libpcap accepts these after 'ether proto \' but compiles them with LLC/SNAP
# logic that bpfkit does not implement.
LLC_PROTO_NAMES = ("iso", "stp", "ipx", "netbeui", "atalk", "aarp")

# Protocol abbreviations usable as primitives: name -> (ipv4 proto, ipv6 proto)
TRANSPORT_ABBREV = {
    "tcp": (6, 6), "udp": (17, 17), "sctp": (132, 132),
    "icmp": (1, None), "igmp": (2, None), "igrp": (9, None),
    "vrrp": (112, None), "carp": (112, None),
    "icmp6": (None, 58), "pim": (103, 103), "ah": (51, 51), "esp": (50, 50),
}

NAMED_CONSTANTS = {
    "tcpflags": 13, "tcp-fin": 0x01, "tcp-syn": 0x02, "tcp-rst": 0x04,
    "tcp-push": 0x08, "tcp-ack": 0x10, "tcp-urg": 0x20, "tcp-ece": 0x40,
    "tcp-cwr": 0x80,
    "icmptype": 0, "icmpcode": 1,
    "icmp-echoreply": 0, "icmp-unreach": 3, "icmp-sourcequench": 4,
    "icmp-redirect": 5, "icmp-echo": 8, "icmp-routeradvert": 9,
    "icmp-routersolicit": 10, "icmp-timxceed": 11, "icmp-paramprob": 12,
    "icmp-tstamp": 13, "icmp-tstampreply": 14, "icmp-ireq": 15,
    "icmp-ireqreply": 16, "icmp-maskreq": 17, "icmp-maskreply": 18,
    "icmp6type": 0, "icmp6code": 1,
    "icmp6-destinationunreach": 1, "icmp6-packettoobig": 2,
    "icmp6-timeexceeded": 3, "icmp6-parameterproblem": 4,
    "icmp6-echo": 128, "icmp6-echoreply": 129,
    "icmp6-multicastlistenerquery": 130, "icmp6-multicastlistenerreportv1": 131,
    "icmp6-multicastlistenerdone": 132, "icmp6-routersolicit": 133,
    "icmp6-routeradvert": 134, "icmp6-neighborsolicit": 135,
    "icmp6-neighboradvert": 136, "icmp6-redirect": 137,
    "icmp6-multicastlistenerreportv2": 143,
}

# Built-in service table so air-gapped hosts without a full /etc/services work.
SERVICES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "dns": 53, "bootps": 67, "bootpc": 68, "tftp": 69,
    "http": 80, "www": 80, "kerberos": 88, "pop3": 110, "sunrpc": 111,
    "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139,
    "imap": 143, "snmp": 161, "snmp-trap": 162, "snmptrap": 162, "bgp": 179,
    "ldap": 389, "https": 443, "microsoft-ds": 445, "isakmp": 500,
    "syslog": 514, "submission": 587, "ldaps": 636, "imaps": 993,
    "pop3s": 995, "openvpn": 1194, "ms-sql-s": 1433, "radius": 1812,
    "radius-acct": 1813, "nfs": 2049, "mysql": 3306, "rdp": 3389,
    "ms-wbt-server": 3389, "sip": 5060, "postgresql": 5432, "x11": 6000,
    "modbus": 502, "dnp": 20000, "dnp3": 20000, "bacnet": 47808,
    "iec-104": 2404, "s7comm": 102, "iso-tsap": 102, "opcua": 4840,
    "mqtt": 1883, "coap": 5683, "netconf": 830,
}

PROTO_QUALS = ("ether", "link", "ip", "ip6", "arp", "rarp", "tcp", "udp",
               "sctp", "icmp", "icmp6", "igmp", "igrp", "pim", "vrrp", "carp",
               "ah", "esp")
DIR_QUALS = ("src", "dst")
TYPE_QUALS = ("host", "net", "port", "portrange", "proto", "gateway", "protochain")
UNSUPPORTED_WORDS = ("mpls", "pppoed", "pppoes", "geneve", "vxlan", "wlan",
                     "type", "subtype", "dir", "ra", "ta", "addr1", "addr2",
                     "addr3", "addr4", "fddi", "tr", "decnet", "iso", "clnp",
                     "esis", "isis", "atalk", "aarp", "stp", "ipx", "netbeui",
                     "lat", "moprc", "mopdl", "ifname", "on", "rnr", "rulenum",
                     "reason", "rset", "ruleset", "srnr", "subrulenum",
                     "action", "inbound", "outbound", "llc", "hdlc")


# --------------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------------

_RE_MAC = re.compile(r"([0-9A-Fa-f]{1,2})([:.-])([0-9A-Fa-f]{1,2})(?:\2[0-9A-Fa-f]{1,2}){4}(?![0-9A-Za-z:.])")
_RE_MAC_DOT = re.compile(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Za-z.])")
_RE_V6_CHUNK = re.compile(r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:/\d+)?")
_RE_HEX = re.compile(r"0[xX][0-9A-Fa-f]+(?![0-9A-Za-z_])")
_RE_DOTTED = re.compile(r"\d+(?:\.\d+){1,3}(?:/\d+)?(?![0-9A-Za-z_])")
_RE_NUM = re.compile(r"\d+(?:/\d+)?(?![0-9A-Za-z_.])")
_RE_RANGE = re.compile(r"(\d+)-(\d+)(?![0-9A-Za-z_.])")
_RE_ID = re.compile(r"\\?[A-Za-z0-9_][A-Za-z0-9_.\-]*")
_OPS = ("&&", "||", "<<", ">>", "<=", ">=", "==", "!=", "(", ")", "[", "]",
        ":", "+", "-", "*", "/", "%", "&", "|", "^", "<", ">", "=", "!")


class Tok(object):
    __slots__ = ("kind", "val", "pos")

    def __init__(self, kind, val, pos):
        self.kind, self.val, self.pos = kind, val, pos

    def __repr__(self):
        return "%s:%r" % (self.kind, self.val)


def tokenize(text):
    toks = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if toks and toks[-1].kind == "id" and toks[-1].val == "portrange":
            m = _RE_RANGE.match(text, i)
            if m:
                toks.append(Tok("range", m.group(0), i))
                i = m.end()
                continue
        m = _RE_MAC.match(text, i) or _RE_MAC_DOT.match(text, i)
        if m:
            toks.append(Tok("mac", m.group(0), i))
            i = m.end()
            continue
        m = _RE_V6_CHUNK.match(text, i)
        if m and m.group(0).count(":") >= 2:
            chunk = m.group(0)
            try:
                ipaddress.IPv6Network(chunk, strict=False)
                toks.append(Tok("ip6", chunk, i))
                i = m.end()
                continue
            except ValueError:
                pass
        m = _RE_HEX.match(text, i)
        if m:
            toks.append(Tok("num", m.group(0), i))
            i = m.end()
            continue
        m = _RE_DOTTED.match(text, i)
        if m:
            toks.append(Tok("ip4", m.group(0), i))
            i = m.end()
            continue
        m = _RE_NUM.match(text, i)
        if m:
            toks.append(Tok("num", m.group(0), i))
            i = m.end()
            continue
        if c.isalpha() or c == "\\" or c == "_":
            m = _RE_ID.match(text, i)
            word = m.group(0).rstrip(".-")
            toks.append(Tok("id", word, i))
            i += len(word)
            continue
        for op in _OPS:
            if text.startswith(op, i):
                toks.append(Tok("op", op, i))
                i += len(op)
                break
        else:
            raise FilterSyntaxError("unexpected character %r at offset %d" % (c, i))
    toks.append(Tok("eof", None, n))
    return toks


# --------------------------------------------------------------------------
# Packet context: link-layer handling
# --------------------------------------------------------------------------

class Ctx(object):
    """Per-packet evaluation context; mirrors how libpcap addresses bytes."""
    __slots__ = ("data", "wirelen", "lt", "n")

    def __init__(self, pkt):
        self.data = pkt.data
        self.wirelen = pkt.wirelen
        self.lt = pkt.linktype
        self.n = len(pkt.data)

    def load(self, off, size):
        if off < 0 or off + size > self.n:
            raise _Reject()
        d = self.data
        if size == 1:
            return d[off]
        if size == 2:
            return (d[off] << 8) | d[off + 1]
        return struct.unpack_from(">I", d, off)[0]

    def bytes_eq(self, off, value):
        if off + len(value) > self.n:
            raise _Reject()
        return self.data[off:off + len(value)] == value

    # --- link layer -------------------------------------------------------
    def nl(self, depth):
        lt = self.lt
        if lt == 1:
            return 14 + 4 * depth
        if depth:
            raise FilterUnsupported("'vlan' is only supported on Ethernet captures")
        if lt == 113:
            return 16
        if lt == 276:
            return 20
        if lt in (0, 108):
            return 4
        if lt in (101, 228, 229):
            return 0
        raise FilterUnsupported("link type %d is not supported by the built-in filter engine" % lt)

    def ethertype(self, depth):
        lt = self.lt
        if lt == 1:
            return self.load(12 + 4 * depth, 2)
        if lt == 113:
            return self.load(14, 2)
        if lt == 276:
            return self.load(0, 2)
        if lt in (0, 108):
            af = self.load(0, 4)
            if lt == 0:  # NULL: host byte order of the capturing machine
                af_le = struct.unpack_from("<I", self.data, 0)[0]
                af = af_le if af_le < 256 else af
            if af == 2:
                return ETH_IP
            if af in (10, 24, 28, 30):
                return ETH_IP6
            return -1
        if lt in (101, 228, 229):
            if lt == 228:
                return ETH_IP
            if lt == 229:
                return ETH_IP6
            v = self.load(0, 1) >> 4
            return ETH_IP if v == 4 else ETH_IP6 if v == 6 else -1
        raise FilterUnsupported("link type %d is not supported by the built-in filter engine" % lt)

    def require_ether(self, what):
        if self.lt != 1:
            raise FilterUnsupported("'%s' needs an Ethernet capture (this one is link type %d)" % (what, self.lt))


def _is_ip(c, d):
    return c.ethertype(d) == ETH_IP


def _is_ip6(c, d):
    return c.ethertype(d) == ETH_IP6


def _ip_proto(c, d, proto):
    return _is_ip(c, d) and c.load(c.nl(d) + 9, 1) == proto


def _ip6_proto(c, d, proto):
    if not _is_ip6(c, d):
        return False
    nl = c.nl(d)
    nh = c.load(nl + 6, 1)
    if nh == proto:
        return True
    return nh == 44 and c.load(nl + 40, 1) == proto


def _ip_first_frag(c, nl):
    return (c.load(nl + 6, 2) & 0x1FFF) == 0


# --------------------------------------------------------------------------
# AST nodes
# --------------------------------------------------------------------------

class Node(object):
    def ev(self, c):
        raise NotImplementedError


class And(Node):
    def __init__(self, a, b):
        self.a, self.b = a, b

    def ev(self, c):
        return self.a.ev(c) and self.b.ev(c)

    def __str__(self):
        return "(%s and %s)" % (self.a, self.b)


class Or(Node):
    def __init__(self, a, b):
        self.a, self.b = a, b

    def ev(self, c):
        return self.a.ev(c) or self.b.ev(c)

    def __str__(self):
        return "(%s or %s)" % (self.a, self.b)


class Not(Node):
    def __init__(self, a):
        self.a = a

    def ev(self, c):
        return not self.a.ev(c)

    def __str__(self):
        return "(not %s)" % self.a


class Fn(Node):
    """A primitive implemented by a closure over the context."""

    def __init__(self, desc, fn):
        self.desc, self.fn = desc, fn

    def ev(self, c):
        return self.fn(c)

    def __str__(self):
        return self.desc


# Arithmetic ----------------------------------------------------------------

class Const(object):
    def __init__(self, v):
        self.v = v & 0xFFFFFFFF

    def val(self, c):
        return self.v

    def __str__(self):
        return str(self.v)


class Len(object):
    def val(self, c):
        return c.wirelen

    def __str__(self):
        return "len"


class Load(object):
    def __init__(self, proto, index, size, depth):
        self.proto, self.index, self.size, self.depth = proto, index, size, depth

    def __str__(self):
        return "%s[%s:%d]" % (self.proto, self.index, self.size)

    def val(self, c):
        p, d = self.proto, self.depth
        if p in ("ether", "link"):
            base = 0
        elif p == "ip":
            if not _is_ip(c, d):
                raise _NoProto()
            base = c.nl(d)
        elif p == "ip6":
            if not _is_ip6(c, d):
                raise _NoProto()
            base = c.nl(d)
        elif p in ("arp", "rarp"):
            if c.ethertype(d) != (ETH_ARP if p == "arp" else ETH_RARP):
                raise _NoProto()
            base = c.nl(d)
        elif p == "icmp6":
            if not _is_ip6(c, d):
                raise _NoProto()
            nl = c.nl(d)
            if c.load(nl + 6, 1) != 58:
                raise _NoProto()
            base = nl + 40
        else:  # transport protocols: IPv4 only, first fragment only
            v4, _v6 = TRANSPORT_ABBREV[p]
            if v4 is None or not _is_ip(c, d):
                raise _NoProto()
            nl = c.nl(d)
            if c.load(nl + 9, 1) != v4 or not _ip_first_frag(c, nl):
                raise _NoProto()
            base = nl + (c.load(nl, 1) & 0x0F) * 4
        off = base + self.index.val(c)
        return c.load(off, self.size)


class BinOp(object):
    def __init__(self, op, a, b):
        self.op, self.a, self.b = op, a, b

    def __str__(self):
        return "(%s %s %s)" % (self.a, self.op, self.b)

    def val(self, c):
        x, y, op = self.a.val(c), self.b.val(c), self.op
        if op == "+":
            r = x + y
        elif op == "-":
            r = x - y
        elif op == "*":
            r = x * y
        elif op == "/":
            if y == 0:
                raise _Reject()
            r = x // y
        elif op == "%":
            if y == 0:
                raise _Reject()
            r = x % y
        elif op == "&":
            r = x & y
        elif op == "|":
            r = x | y
        elif op == "^":
            r = x ^ y
        elif op == "<<":
            r = (x << y) if y < 32 else 0
        elif op == ">>":
            r = (x >> y) if y < 32 else 0
        else:
            raise AssertionError(op)
        return r & 0xFFFFFFFF


def _static_value(node):
    """The value of an arithmetic node if it is known without a packet, else None.
    Mirrors the constant folding libpcap does before it checks for / 0."""
    if isinstance(node, Const):
        return node.v
    if isinstance(node, BinOp):
        a, b = _static_value(node.a), _static_value(node.b)
        if node.op in ("&", "*") and 0 in (a, b):
            return 0
        if node.op in ("-", "^") and str(node.a) == str(node.b):
            return 0  # libpcap's value numbering sees x - x and x ^ x as 0
        if a is not None and b is not None:
            try:
                return BinOp(node.op, Const(a), Const(b)).val(None)
            except _Reject:
                return None
    if isinstance(node, Neg):
        v = _static_value(node.a)
        return None if v is None else (-v) & 0xFFFFFFFF
    return None


class Neg(object):
    def __init__(self, a):
        self.a = a

    def val(self, c):
        return (-self.a.val(c)) & 0xFFFFFFFF

    def __str__(self):
        return "-%s" % self.a


class Relation(Node):
    def __init__(self, op, a, b):
        self.op, self.a, self.b = op, a, b

    def __str__(self):
        return "%s %s %s" % (self.a, self.op, self.b)

    def ev(self, c):
        try:
            x = self.a.val(c)
            y = self.b.val(c)
        except _NoProto:
            return False
        op = self.op
        if op in ("=", "=="):
            return x == y
        if op == "!=":
            return x != y
        if op == ">":
            return x > y
        if op == "<":
            return x < y
        if op == ">=":
            return x >= y
        return x <= y


# --------------------------------------------------------------------------
# Value helpers
# --------------------------------------------------------------------------

def _parse_mac(text):
    if "." in text and len(text) == 14:
        h = text.replace(".", "")
        return bytes(bytearray.fromhex(h))
    parts = re.split(r"[:.-]", text)
    return bytes(bytearray(int(p, 16) for p in parts))


def _parse_num(text):
    if text.lower().startswith("0x"):
        return int(text, 16)
    if len(text) > 1 and text.startswith("0") and text.isdigit():
        try:
            return int(text, 8)  # libpcap accepts C-style octal
        except ValueError:
            pass
    return int(text)


def _ip4_net(text, mask_text=None):
    """Parse a (possibly abbreviated) IPv4 network like libpcap's 'net'."""
    if "/" in text:
        addr, plen = text.split("/", 1)
        plen = int(plen)
    else:
        addr, plen = text, None
    octets = addr.split(".")
    if len(octets) > 4 or any(not o.isdigit() or int(o) > 255 for o in octets):
        raise FilterSyntaxError("bad IPv4 address %r" % text)
    if plen is None and mask_text is None:
        plen = 8 * len(octets)  # 'net 10' -> 10.0.0.0/8, 'net 10.1' -> /16
    octets = octets + ["0"] * (4 - len(octets))
    a = struct.unpack(">I", bytes(bytearray(int(o) for o in octets)))[0]
    if mask_text is not None:
        m = struct.unpack(">I", ipaddress.IPv4Address(mask_text).packed)[0]
    else:
        if plen > 32:
            raise FilterSyntaxError("bad prefix length in %r" % text)
        m = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
    if a & ~m & 0xFFFFFFFF:
        raise FilterSyntaxError("non-network bits set in %r" % text)
    return a, m


# Name resolution is OFF by default: on an air-gapped host getaddrinfo() can
# hang until the resolver times out, or send the name to an internal DNS
# server. Callers opt in with compile_filter(..., allow_dns=True) or --allow-dns.
ALLOW_DNS = False


def _resolve_host(name, allow_dns):
    if not allow_dns:
        raise FilterSyntaxError(
            "%r looks like a host name, and name resolution is disabled (air-gapped "
            "default). Use the IP address, or pass --allow-dns to resolve it." % name)
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, UnicodeError):
        raise FilterSyntaxError(
            "unknown host %r (no DNS on an air-gapped system? use the IP address instead)" % name)
    out = []
    for fam, _t, _p, _cn, sa in infos:
        if sa[0] not in out:
            out.append(sa[0])
    return out


def _service_port(name):
    n = name.lower().lstrip("\\")
    if n in SERVICES:
        return SERVICES[n]
    for proto in ("tcp", "udp"):
        try:
            return socket.getservbyname(n, proto)
        except (OSError, socket.error):
            pass
    raise FilterSyntaxError("unknown port/service name %r" % name)


# --------------------------------------------------------------------------
# Primitive builders (closures)
# --------------------------------------------------------------------------

def _dir_combine(dirq, src_fn, dst_fn):
    if dirq == "src":
        return src_fn
    if dirq == "dst":
        return dst_fn
    if dirq == "src and dst":
        return lambda c: src_fn(c) and dst_fn(c)
    return lambda c: src_fn(c) or dst_fn(c)


def _host4(proto, dirq, addr, mask, d):
    def ip_part(c):
        if not _is_ip(c, d):
            return False
        nl = c.nl(d)
        return _dir_combine(dirq,
                            lambda c: (c.load(nl + 12, 4) & mask) == addr,
                            lambda c: (c.load(nl + 16, 4) & mask) == addr)(c)

    def arp_part(et):
        def f(c):
            if c.ethertype(d) != et:
                return False
            nl = c.nl(d)
            return _dir_combine(dirq,
                                lambda c: (c.load(nl + 14, 4) & mask) == addr,
                                lambda c: (c.load(nl + 24, 4) & mask) == addr)(c)
        return f

    if proto in (None, "link"):
        a, r = arp_part(ETH_ARP), arp_part(ETH_RARP)
        return lambda c: ip_part(c) or a(c) or r(c)
    if proto == "ip":
        return ip_part
    if proto == "arp":
        return arp_part(ETH_ARP)
    if proto == "rarp":
        return arp_part(ETH_RARP)
    raise FilterSyntaxError("'%s' modifier applied to an IPv4 host/net" % proto)


def _host6(proto, dirq, net, d):
    a = net.network_address.packed
    plen = net.prefixlen
    full, rem = plen // 8, plen % 8
    mbyte = (0xFF << (8 - rem)) & 0xFF if rem else 0

    def matches(c, off):
        if off + 16 > c.n:
            raise _Reject()
        b = c.data[off:off + 16]
        if b[:full] != a[:full]:
            return False
        return not rem or (b[full] & mbyte) == a[full]

    if proto not in (None, "ip6", "link"):
        raise FilterSyntaxError("'%s' modifier applied to an IPv6 host/net" % proto)

    def f(c):
        if not _is_ip6(c, d):
            return False
        nl = c.nl(d)
        return _dir_combine(dirq, lambda c: matches(c, nl + 8), lambda c: matches(c, nl + 24))(c)
    return f


def _ether_host(dirq, mac):
    def f(c):
        c.require_ether("ether host")
        return _dir_combine(dirq, lambda c: c.bytes_eq(6, mac), lambda c: c.bytes_eq(0, mac))(c)
    return f


def _port_fn(proto, dirq, lo, hi, d):
    if proto in (None, "ip", "ip6"):
        protos = (6, 17, 132)
    elif proto in ("tcp", "udp", "sctp"):
        protos = (TRANSPORT_ABBREV[proto][0],)
    else:
        raise FilterSyntaxError("'%s' modifier applied to port" % proto)

    def check(c, base):
        return _dir_combine(dirq,
                            lambda c: lo <= c.load(base, 2) <= hi,
                            lambda c: lo <= c.load(base + 2, 2) <= hi)(c)

    def v4(c):
        if not _is_ip(c, d):
            return False
        nl = c.nl(d)
        if c.load(nl + 9, 1) not in protos or not _ip_first_frag(c, nl):
            return False
        return check(c, nl + (c.load(nl, 1) & 0x0F) * 4)

    def v6(c):
        if not _is_ip6(c, d):
            return False
        nl = c.nl(d)
        if c.load(nl + 6, 1) not in protos:
            return False
        return check(c, nl + 40)

    if proto == "ip":
        return v4
    if proto == "ip6":
        return v6
    return lambda c: v4(c) or v6(c)


def _proto_abbrev(name, d):
    if name == "ip":
        return lambda c: _is_ip(c, d)
    if name == "ip6":
        return lambda c: _is_ip6(c, d)
    if name == "arp":
        return lambda c: c.ethertype(d) == ETH_ARP
    if name == "rarp":
        return lambda c: c.ethertype(d) == ETH_RARP
    v4, v6 = TRANSPORT_ABBREV[name]
    if v4 is not None and v6 is not None:
        return lambda c: _ip_proto(c, d, v4) or _ip6_proto(c, d, v6)
    if v4 is not None:
        return lambda c: _ip_proto(c, d, v4)
    return lambda c: _ip6_proto(c, d, v6)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

class _Quals(object):
    __slots__ = ("proto", "dir", "typ")

    def __init__(self, proto=None, dirq=None, typ=None):
        self.proto, self.dir, self.typ = proto, dirq, typ


class Parser(object):
    def __init__(self, text, allow_dns=False):
        self.text = text
        self.allow_dns = allow_dns
        self.toks = tokenize(text)
        self.i = 0
        self.vlan_depth = 0
        self.last = None  # last explicit qualifiers, for bare-value carry-over

    # token helpers
    @property
    def t(self):
        return self.toks[self.i]

    def peek(self, k=1):
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def adv(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def is_op(self, *ops):
        return self.t.kind == "op" and self.t.val in ops

    def is_word(self, *words):
        return self.t.kind == "id" and self.t.val in words

    def err(self, msg):
        t = self.t
        where = "end of expression" if t.kind == "eof" else "%r (offset %d)" % (t.val, t.pos)
        raise FilterSyntaxError("%s near %s" % (msg, where))

    # grammar
    def parse(self):
        if self.t.kind == "eof":
            return None
        node = self.expr()
        if self.t.kind != "eof":
            self.err("unexpected token")
        return node

    def expr(self):
        node = self.unary()
        while True:
            if self.is_word("and") or self.is_op("&&"):
                self.adv()
                node = And(node, self.unary())
            elif self.is_word("or") or self.is_op("||"):
                self.adv()
                node = Or(node, self.unary())
            else:
                return node

    def unary(self):
        if self.is_word("not") or self.is_op("!"):
            self.adv()
            return Not(self.unary())
        save, depth, last = self.i, self.vlan_depth, self.last
        try:
            return self.relation()
        except _FatalSyntaxError:
            raise
        except FilterSyntaxError:
            self.i, self.vlan_depth, self.last = save, depth, last
        if self.is_op("("):
            self.adv()
            e = self.expr()
            if not self.is_op(")"):
                self.err("expected ')'")
            self.adv()
            return e
        return self.primitive()

    # --- relations ------------------------------------------------------
    def relation(self):
        a = self.arith()
        if not self.is_op("=", "==", "!=", "<", ">", "<=", ">="):
            self.err("expected comparison operator")
        op = self.adv().val
        b = self.arith()
        return Relation(op, a, b)

    _PREC = [("|",), ("^",), ("&",), ("<<", ">>"), ("+", "-"), ("*", "/", "%")]

    def arith(self, level=0):
        if level == len(self._PREC):
            return self.arith_unary()
        node = self.arith(level + 1)
        while self.t.kind == "op" and self.t.val in self._PREC[level]:
            op = self.adv().val
            rhs = self.arith(level + 1)
            if op in ("/", "%") and _static_value(rhs) == 0:
                # libpcap's optimiser folds the divisor and refuses the filter
                raise _FatalSyntaxError("%s by zero" % ("division" if op == "/" else "modulus"))
            node = BinOp(op, node, rhs)
        return node

    def arith_unary(self):
        if self.is_op("-"):
            self.adv()
            return Neg(self.arith_unary())
        t = self.t
        if self.is_op("("):
            self.adv()
            e = self.arith()
            if not self.is_op(")"):
                self.err("expected ')'")
            self.adv()
            return e
        if t.kind == "num":
            self.adv()
            if "/" in t.val:
                self.err("unexpected '/'")
            return Const(_parse_num(t.val))
        if t.kind == "id":
            w = t.val
            if w == "len":
                self.adv()
                return Len()
            if w in NAMED_CONSTANTS:
                self.adv()
                return Const(NAMED_CONSTANTS[w])
            if w in PROTO_QUALS and self.peek().kind == "op" and self.peek().val == "[":
                if w not in ("ether", "link", "ip", "ip6", "arp", "rarp", "icmp6") and w not in TRANSPORT_ABBREV:
                    self.err("cannot index protocol %r" % w)
                self.adv()
                self.adv()  # '['
                idx = self.arith()
                size = 1
                if self.is_op(":"):
                    self.adv()
                    st = self.adv()
                    if st.kind != "num" or st.val not in ("1", "2", "4"):
                        self.err("load size must be 1, 2 or 4")
                    size = int(st.val)
                if not self.is_op("]"):
                    self.err("expected ']'")
                self.adv()
                return Load(w, idx, size, self.vlan_depth)
        self.err("expected arithmetic expression")

    # --- primitives -----------------------------------------------------
    def primitive(self):
        t = self.t
        d = self.vlan_depth
        if t.kind == "id":
            w = t.val
            if w in UNSUPPORTED_WORDS:
                raise FilterUnsupported(
                    "'%s' is not supported by the built-in engine; run the filter "
                    "with tcpdump if it is available" % w)
            if w in ("less", "greater"):
                self.adv()
                n = self._number("%s needs a length" % w)
                if w == "less":
                    return Fn("less %d" % n, lambda c: c.wirelen <= n)
                return Fn("greater %d" % n, lambda c: c.wirelen >= n)
            if w == "vlan":
                self.adv()
                vid = None
                if self.t.kind == "num":
                    vid = _parse_num(self.adv().val)
                self.vlan_depth += 1
                return self._vlan(d, vid)
            if w in ("broadcast", "multicast"):
                self.adv()
                return self._cast(None, w, d)
            if w == "gateway":
                raise FilterUnsupported("'gateway' needs name resolution of ethers/hosts; not supported")
        q = _Quals()
        explicit = False
        if self.t.kind == "id" and self.t.val in PROTO_QUALS:
            q.proto = self.adv().val
            explicit = True
            if self.is_word("broadcast", "multicast"):
                return self._cast(q.proto, self.adv().val, d)
            if self.is_word("proto"):
                self.adv()
                return self._proto_qual(q.proto, d)
            if self.is_word("protochain"):
                raise FilterUnsupported("'protochain' is not supported; use tcpdump")
            if not (self.is_word(*DIR_QUALS) or self.is_word(*TYPE_QUALS)):
                if q.proto in ("ether", "link"):
                    self.err("'%s' must be followed by host/src/dst/proto/broadcast/multicast or [index]" % q.proto)
                self.last = None
                return Fn(q.proto, _proto_abbrev(q.proto, d))
        if self.is_word(*DIR_QUALS):
            q.dir = self.adv().val
            explicit = True
            if (self.is_word("or", "and") and self.peek().kind == "id"
                    and self.peek().val in DIR_QUALS and self.peek().val != q.dir):
                conj = self.adv().val
                self.adv()
                q.dir = "src %s dst" % conj
        if self.is_word(*TYPE_QUALS):
            q.typ = self.adv().val
            explicit = True
            if q.typ == "proto":
                return self._proto_qual(q.proto, d)
            if q.typ in ("gateway", "protochain"):
                raise FilterUnsupported("'%s' is not supported; use tcpdump" % q.typ)
        if not explicit:
            if self.last is None:
                self.err("a bare value needs a qualifier (host/net/port/...)")
            q = self.last
        if self.t.kind not in ("id", "num", "ip4", "ip6", "mac", "range"):
            self.err("expected a value (address, port, name)")
        if self.t.kind == "id" and self.t.val in ("and", "or", "not"):
            self.err("expected a value")
        val = self.adv()
        if explicit:
            self.last = q
        return self._qualified(q, val, d)

    def _number(self, msg):
        if self.t.kind != "num":
            self.err(msg)
        return _parse_num(self.adv().val)

    def _vlan(self, d, vid):
        def f(c):
            c.require_ether("vlan")
            if c.load(12 + 4 * d, 2) not in VLAN_TPIDS:
                return False
            return vid is None or (c.load(14 + 4 * d, 2) & 0x0FFF) == vid
        return Fn("vlan" + ("" if vid is None else " %d" % vid), f)

    def _cast(self, proto, kind, d):
        if proto in (None, "ether", "link"):
            if kind == "broadcast":
                bc = b"\xff" * 6

                def f(c):
                    c.require_ether("broadcast")
                    return c.bytes_eq(0, bc)
            else:
                def f(c):
                    c.require_ether("multicast")
                    return bool(c.load(0, 1) & 1)
            return Fn("ether " + kind, f)
        if proto == "ip":
            if kind == "multicast":
                return Fn("ip multicast", lambda c: _is_ip(c, d) and c.load(c.nl(d) + 16, 1) >= 224)
            return Fn("ip broadcast", lambda c: _is_ip(c, d) and c.load(c.nl(d) + 16, 4) in (0xFFFFFFFF, 0))
        if proto == "ip6" and kind == "multicast":
            return Fn("ip6 multicast", lambda c: _is_ip6(c, d) and c.load(c.nl(d) + 24, 1) == 0xFF)
        self.err("'%s %s' is not valid" % (proto, kind))

    def _proto_qual(self, proto, d):
        t = self.adv()
        if t.kind == "num":
            v = _parse_num(t.val)
        elif t.kind == "id":
            name = t.val.lstrip("\\")
            table = ETHER_PROTO_NAMES if proto in ("ether", "link") else IP_PROTO_NAMES
            if proto in ("ether", "link") and name in LLC_PROTO_NAMES:
                raise FilterUnsupported(
                    "'ether proto \\%s' uses LLC/SNAP matching that the built-in engine does "
                    "not implement; use tcpdump" % name)
            if name not in table:
                raise FilterSyntaxError("unknown protocol name %r" % name)
            v = table[name]
        else:
            self.i -= 1
            self.err("expected protocol number or name")
        desc = "%s proto %d" % (proto or "", v)
        if proto in ("ether", "link"):
            # a plain EtherType compare, even for 0x8100: unlike 'vlan' it accepts
            # no other TPIDs and does not shift later offsets (as libpcap compiles it)
            return Fn(desc, lambda c: c.ethertype(d) == v)
        if proto == "ip":
            return Fn(desc, lambda c: _ip_proto(c, d, v))
        if proto == "ip6":
            return Fn(desc, lambda c: _ip6_proto(c, d, v))
        if proto is None:
            return Fn(desc, lambda c: _ip_proto(c, d, v) or _ip6_proto(c, d, v))
        raise FilterSyntaxError("'%s proto' is not valid" % proto)

    def _qualified(self, q, tok, d):
        proto, dirq, typ = q.proto, q.dir, q.typ
        kind, text = tok.kind, tok.val
        desc = " ".join(x for x in (proto, dirq, typ, text) if x)

        if typ in ("port", "portrange"):
            if typ == "portrange":
                if kind == "range":
                    lo_t, hi_t = text.split("-")
                    lo, hi = self._port_value(lo_t), self._port_value(hi_t)
                elif kind == "num":
                    lo = hi = self._port_value(text)
                else:
                    self.i -= 1
                    self.err("portrange needs low-high (numbers)")
                if lo > hi:
                    lo, hi = hi, lo
            else:
                if kind not in ("num", "id"):
                    self.err("bad port")
                lo = hi = self._port_value(text)
            return Fn(desc, _port_fn(proto, dirq, lo, hi, d))

        if typ == "net":
            if kind == "ip6":
                net = ipaddress.IPv6Network(text, strict=True)
                return Fn(desc, _host6(proto, dirq, net, d))
            mask_text = None
            if self.is_word("mask"):
                self.adv()
                mt = self.adv()
                if mt.kind != "ip4":
                    self.err("expected netmask")
                mask_text = mt.val
            if kind not in ("ip4", "num"):
                self.err("bad network")
            a, m = _ip4_net(text, mask_text)
            return Fn(desc, _host4(proto, dirq, a, m, d))

        # host (explicit or default)
        if kind == "mac" or proto in ("ether", "link"):
            if kind != "mac":
                raise FilterSyntaxError("'%s' needs a MAC address (no ethers database offline)" % desc)
            if proto not in (None, "ether", "link"):
                raise FilterSyntaxError("'%s' modifier applied to a MAC address" % proto)
            return Fn(desc, _ether_host(dirq, _parse_mac(text)))
        if kind == "ip6":
            net = ipaddress.IPv6Network(text, strict=False)
            if "/" in text and typ != "net":
                raise FilterSyntaxError("use 'net' with a prefix length: %s" % text)
            return Fn(desc, _host6(proto, dirq, net, d))
        if kind in ("ip4", "num"):
            if "/" in text or (kind == "ip4" and text.count(".") < 3) or kind == "num":
                if typ == "host":
                    raise FilterSyntaxError("'host %s' is not a complete IPv4 address" % text)
                a, m = _ip4_net(text)
                return Fn(desc, _host4(proto, dirq, a, m, d))
            a = struct.unpack(">I", ipaddress.IPv4Address(text).packed)[0]
            return Fn(desc, _host4(proto, dirq, a, 0xFFFFFFFF, d))
        # hostname
        addrs = _resolve_host(text, self.allow_dns)
        node = None
        for ad in addrs:
            if ":" in ad:
                f = _host6(proto, dirq, ipaddress.IPv6Network(ad), d)
            else:
                f = _host4(proto, dirq, struct.unpack(">I", socket.inet_aton(ad))[0], 0xFFFFFFFF, d)
            n = Fn(desc, f)
            node = n if node is None else Or(node, n)
        return node

    def _port_value(self, text):
        if re.match(r"^(0x[0-9a-fA-F]+|\d+)$", text):
            v = _parse_num(text)
        else:
            v = _service_port(text)
        if v > 65535:
            raise FilterSyntaxError("port %s out of range" % text)
        return v


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

class BPFFilter(object):
    def __init__(self, text, allow_dns=None):
        self.text = text
        if allow_dns is None:
            allow_dns = ALLOW_DNS
        try:
            self.root = Parser(text, allow_dns).parse()
        except ValueError as e:  # bad address / number caught by ipaddress/int()
            raise FilterSyntaxError(str(e))

    def match(self, pkt):
        if self.root is None:
            return True
        try:
            return bool(self.root.ev(Ctx(pkt)))
        except _Reject:
            return False

    def __str__(self):
        return str(self.root) if self.root is not None else "(match everything)"


def compile_filter(text, allow_dns=None):
    """Parse a tcpdump-style filter. Raises FilterSyntaxError/FilterUnsupported.

    Host names are only resolved when allow_dns is True (default: the module
    setting ALLOW_DNS, which is False)."""
    return BPFFilter(text or "", allow_dns)
