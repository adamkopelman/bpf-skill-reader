"""bpfgen - find patterns in a capture and generate a BPF filter for them.

Pure Python standard library; works offline / air-gapped.

Subcommands
  profile  FILE              what is in the capture, with a ready-made BPF for
                             every notable group (hosts, conversations, ports,
                             scans, DNS names, HTTP, TLS SNI, Modbus, VLANs...)
  suggest  FILE TARGET...    learn the shortest BPF that selects the target
                             packets and rejects everything else
  test     FILE FILTER [TARGET...]
                             score a filter: matches, precision/recall vs
                             the target, and the packets it gets wrong

TARGET options (combine them; all must hold):
  --packets 12,15-20         packet numbers (as shown by capread / Wireshark)
  --where 'BPF'              packets matching a filter (e.g. a broad one)
  --contains TEXT            payload contains this ASCII text
  --contains-hex HEX         payload contains these bytes (e.g. 160301)
  --flow-of N                every packet of the same conversation as packet N
  --ignore 'BPF'             packets you do not care about either way

Examples:
  bpfgen.py profile traffic.cap
  bpfgen.py suggest traffic.cap --packets 40,42,44,46,48,50,52,54
  bpfgen.py suggest traffic.cap --contains "GET /firmware"
  bpfgen.py suggest traffic.cap --flow-of 25 --ignore arp
  bpfgen.py test traffic.cap 'tcp port 502' --contains-hex 0006
"""

import argparse
import collections
import ipaddress
import json
import math
import sys

from . import decode as dec
from .bpf import compile_filter, FilterSyntaxError, FilterUnsupported, SERVICES, NAMED_CONSTANTS
from .pcapio import read_packets, CaptureFormatError
from .util import (parse_index_spec, popcount, bitset_from_indices, bits_to_positions,
                   find_tcpdump, tcpdump_matching_keys, tcpdump_compile,
                   LINKTYPE_TO_DLT_NAME)

SERVICE_PORTS = set(SERVICES.values())
V4_ABBREV = {6: "tcp", 17: "udp", 1: "icmp", 2: "igmp", 132: "sctp", 103: "pim",
             112: "vrrp", 51: "ah", 50: "esp"}
V6_ABBREV = {6: "tcp", 17: "udp", 58: "icmp6", 132: "sctp", 103: "pim", 51: "ah", 50: "esp"}
ICMP_NAMES = dict((v, k) for k, v in NAMED_CONSTANTS.items()
                  if k.startswith("icmp-") and k not in ("icmp-echo",))
ICMP_NAMES[8] = "icmp-echo"
TCP_PAYLOAD = "tcp[((tcp[12:1] & 0xf0) >> 2)%s%s]"
IP6_TCP_PAYLOAD = "ip6[40 + ((ip6[52] & 0xf0) >> 2)%s%s]"

# Feature families. "general" suggestions only use the ones that describe
# *what kind of traffic* it is, so they keep working on future captures.
GENERAL_FAMILIES = {"proto", "host", "net", "port", "vlan", "tcpflags", "icmp",
                    "app", "frag", "ether"}


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

class Capture(object):
    def __init__(self, path, max_packets):
        self.path = path
        self.pkts = []
        self.decoded = []
        self.truncated_load = False
        for p in read_packets(path):
            if max_packets and len(self.pkts) >= max_packets:
                self.truncated_load = True
                break
            self.pkts.append(p)
            self.decoded.append(dec.decode(p))
        self.n = len(self.pkts)
        self.all = (1 << self.n) - 1
        self.linktypes = collections.Counter(p.linktype for p in self.pkts)

    def bits_where(self, pred):
        return bitset_from_indices([i for i in range(self.n) if pred(i)], self.n)

    def bits_filter(self, expr):
        flt = compile_filter(expr)
        return self.bits_where(lambda i: flt.match(self.pkts[i]))


def flow_key(d):
    if d.get("src") is None:
        return None
    a = (d.get("src"), d.get("sport"))
    b = (d.get("dst"), d.get("dport"))
    return (d.get("l3"), d.get("l4") or d.get("proto")) + tuple(sorted([a, b], key=str))


def select_targets(cap, args):
    """Return (target_bits, dontcare_bits, description)."""
    bits = cap.all
    desc = []
    if getattr(args, "packets", None):
        want = parse_index_spec(args.packets)
        bits &= cap.bits_where(lambda i: cap.pkts[i].index in want)
        desc.append("packets %s" % args.packets)
    if getattr(args, "where", None):
        bits &= cap.bits_filter(args.where)
        desc.append("matching '%s'" % args.where)
    if getattr(args, "contains", None):
        needle = args.contains.encode("latin-1")
        bits &= cap.bits_where(lambda i: needle in cap.pkts[i].data)
        desc.append("containing %r" % args.contains)
    if getattr(args, "contains_hex", None):
        needle = bytes(bytearray.fromhex(args.contains_hex.replace(" ", "").replace(":", "")))
        bits &= cap.bits_where(lambda i: needle in cap.pkts[i].data)
        desc.append("containing bytes %s" % needle.hex())
    if getattr(args, "flow_of", None):
        ref = [i for i in range(cap.n) if cap.pkts[i].index == args.flow_of]
        if not ref:
            raise SystemExit("packet #%d not found" % args.flow_of)
        key = flow_key(cap.decoded[ref[0]])
        if key is None:
            raise SystemExit("packet #%d has no IP/ARP addresses to build a flow from" % args.flow_of)
        bits &= cap.bits_where(lambda i: flow_key(cap.decoded[i]) == key)
        desc.append("same conversation as #%d" % args.flow_of)
    if not desc:
        return None, 0, ""
    dontcare = cap.bits_filter(args.ignore) if getattr(args, "ignore", None) else 0
    bits &= ~dontcare
    if dontcare:
        desc.append("ignoring '%s'" % args.ignore)
    return bits, dontcare, ", ".join(desc)


def add_target_args(ap):
    ap.add_argument("--packets", help="target packet numbers, e.g. '12,15-20'")
    ap.add_argument("--where", help="target packets matching this BPF filter")
    ap.add_argument("--contains", help="target packets whose bytes contain this text")
    ap.add_argument("--contains-hex", help="target packets whose bytes contain this hex string")
    ap.add_argument("--flow-of", type=int, help="target the whole conversation of packet N")
    ap.add_argument("--ignore", help="BPF for packets that may match or not (don't care)")


# --------------------------------------------------------------------------
# Feature extraction - every feature is a BPF term with the same semantics as
# the engine in bpf.py (and libpcap).
# --------------------------------------------------------------------------

class Feature(object):
    __slots__ = ("ctx", "term", "family", "cost", "desc", "bits", "neg")

    def __init__(self, ctx, term, family, cost, desc, bits=0, neg=False):
        self.ctx, self.term, self.family, self.cost = ctx, term, family, cost
        self.desc, self.bits, self.neg = desc, bits, neg

    def render(self):
        # Terms are only ever AND-ed together, so a compound term needs
        # parentheses only when negated.
        t = self.term
        if self.neg:
            return "not (%s)" % t if (" and " in t or " or " in t) else "not %s" % t
        return t


def _is_service_port(port, other):
    return port < 1024 or port in SERVICE_PORTS or port <= other


def _payload_terms(d):
    """(term_format(k, size), guard) for the packet's L4 payload, or None."""
    l3, l4 = d.get("l3"), d.get("l4")
    if d.get("frag_off"):
        return None
    if l3 == "ipv4" and l4 == "tcp":
        return lambda k, s: TCP_PAYLOAD % (" + %d" % k if k else "", ":%d" % s if s > 1 else "")
    if l3 == "ipv4" and l4 == "udp":
        return lambda k, s: "udp[%d%s]" % (8 + k, ":%d" % s if s > 1 else "")
    if l3 == "ipv6" and d.get("ip6_direct") and l4 == "tcp":
        return lambda k, s: "ip6[6] = 6 and " + IP6_TCP_PAYLOAD % (" + %d" % k if k else "", ":%d" % s if s > 1 else "")
    if l3 == "ipv6" and d.get("ip6_direct") and l4 == "udp":
        return lambda k, s: "ip6[6] = 17 and ip6[%d%s]" % (48 + k, ":%d" % s if s > 1 else "")
    return None


def packet_features(d):
    """List of (ctx, term, family, cost, description, (varkey, value) or None).

    ctx is the number of VLAN tags the term sits behind (None = absolute
    link-layer offset, valid at any depth)."""
    out = []
    k = len(d["vlans"])

    def add(term, family, cost, desc, ctx=k, var=None):
        out.append((ctx, term, family, cost, desc, var))

    lt = d["linktype"]
    if lt == 1 and "eth_src" in d:
        add("ether src %s" % d["eth_src"], "ether", 3.0, "source MAC", None)
        add("ether dst %s" % d["eth_dst"], "ether", 3.0, "destination MAC", None)
        add("ether host %s" % d["eth_src"], "ether", 2.8, "MAC (either direction)", None)
        add("ether host %s" % d["eth_dst"], "ether", 2.8, "MAC (either direction)", None)
        if d["eth_dst"] == "ff:ff:ff:ff:ff:ff":
            add("ether broadcast", "ether", 2.0, "Ethernet broadcast", None)
        if int(d["eth_dst"][:2], 16) & 1:
            add("ether multicast", "ether", 2.5, "Ethernet multicast/broadcast", None)
        for j, v in enumerate(d["vlans"]):
            add("ether[%d:2] & 0x0fff = %d" % (14 + 4 * j, v), "vlan", 1.5, "VLAN id %d" % v)

    l3, et = d.get("l3"), d.get("ethertype")
    if l3 == "ipv4":
        add("ip", "proto", 1.0, "IPv4")
    elif l3 == "ipv6":
        add("ip6", "proto", 1.0, "IPv6")
    elif l3 == "arp":
        add("arp" if et == 0x0806 else "rarp", "proto", 1.0, "ARP")
    elif isinstance(et, int) and et > 1500 and lt in (1, 113, 276):
        add("ether proto 0x%04x" % et, "proto", 1.5, "EtherType 0x%04x" % et)

    if l3 == "ipv4":
        p = d["proto"]
        add(V4_ABBREV.get(p, "ip proto %d" % p), "proto", 1.0 if p in V4_ABBREV else 1.5, "IP protocol %d" % p)
    elif l3 == "ipv6":
        nh = d.get("ip6_nh")
        eff = d.get("ip6_frag_nh") if nh == 44 else nh
        if eff is not None and eff not in (0, 43, 60):
            add(V6_ABBREV.get(eff, "ip6 proto %d" % eff), "proto", 1.0 if eff in V6_ABBREV else 1.5,
                "IPv6 next header %d" % eff)

    # addresses (ARP addresses count: libpcap's 'host' also matches ARP)
    if d.get("src") and l3 in ("ipv4", "ipv6", "arp"):
        for side in ("src", "dst"):
            a = d[side]
            add("host %s" % a, "host", 2.0, "address (either direction)")
            add("%s host %s" % (side, a), "host", 2.4, "%s address" % side)
            if ":" in a:
                net = ipaddress.IPv6Network(a + "/64", strict=False)
                add("net %s" % net, "net", 3.2, "IPv6 /64")
                add("%s net %s" % (side, net), "net", 3.5, "%s IPv6 /64" % side)
            else:
                for plen, c in ((24, 3.0), (16, 3.4)):
                    net = ipaddress.IPv4Network("%s/%d" % (a, plen), strict=False)
                    add("net %s" % net, "net", c, "IPv4 /%d" % plen)
                    add("%s net %s" % (side, net), "net", c + 0.3, "%s IPv4 /%d" % (side, plen))

    l4 = d.get("l4")
    first_frag = not d.get("frag_off")
    port_ok = (l4 in ("tcp", "udp", "sctp") and "sport" in d and
               ((l3 == "ipv4" and first_frag) or (l3 == "ipv6" and d.get("ip6_direct"))))
    if port_ok:
        sp, dp = d["sport"], d["dport"]
        for side, port, other in (("src", sp, dp), ("dst", dp, sp)):
            svc = _is_service_port(port, other)
            fam = "port" if svc else "eport"
            extra = 0.0 if svc else 3.0
            add("port %d" % port, fam, 2.0 + extra, "port (either direction)")
            add("%s port %d" % (l4, port), fam, 2.1 + extra, "%s port" % l4.upper())
            add("%s port %d" % (side, port), fam, 2.4 + extra, "%s port" % side)
            add("%s %s port %d" % (l4, side, port), fam, 2.5 + extra, "%s %s port" % (l4.upper(), side))

    if l3 == "ipv4" and first_frag and l4 == "tcp" and "flags" in d:
        f = d["flags"]
        if f & 0x12 == 0x02:
            add("tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn", "tcpflags", 2.6, "SYN without ACK (connection attempt)")
        if f & 0x12 == 0x12:
            add("tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)", "tcpflags", 2.7, "SYN+ACK (connection accepted)")
        for bit, name, why in ((0x02, "tcp-syn", "SYN set"), (0x04, "tcp-rst", "RST set (reset/refused)"),
                               (0x01, "tcp-fin", "FIN set (close)"), (0x08, "tcp-push", "PSH set (data)"),
                               (0x20, "tcp-urg", "URG set")):
            if f & bit:
                add("tcp[tcpflags] & %s != 0" % name, "tcpflags", 2.8, why)
        if f & 0x10 == 0:
            add("tcp[tcpflags] & tcp-ack = 0", "tcpflags", 3.0, "ACK not set")
        add("tcp[tcpflags] = 0x%02x" % f, "tcpflags", 3.4, "exact TCP flags [%s]" % dec.flags_str(f))
        add("tcp[14:2] = %d" % d["win"], "fingerprint", 4.5, "TCP window size")
    if l3 == "ipv4" and first_frag and l4 == "icmp":
        t = d["icmp_type"]
        add("icmp[icmptype] = %s" % ICMP_NAMES.get(t, t), "icmp", 2.3, "ICMP type %d" % t)
    if l3 == "ipv6" and d.get("ip6_nh") == 58:
        t = d["icmp_type"]
        add("ip6[6] = 58 and ip6[40] = %d" % t, "icmp", 2.5, "ICMPv6 type %d" % t)
    if l3 == "ipv4" and first_frag and l4 == "udp" and "dns_qr" in d and 53 in (d["sport"], d["dport"]):
        if d["dns_qr"] == "query":
            add("udp[10] & 0x80 = 0", "app", 3.0, "DNS query (QR bit clear)")
        else:
            add("udp[10] & 0x80 != 0", "app", 3.0, "DNS response (QR bit set)")
    if l3 == "ipv4":
        if d.get("frag_off"):
            add("ip[6:2] & 0x1fff != 0", "frag", 3.0, "non-first IPv4 fragment")
        if d.get("mf"):
            add("ip[6] & 0x20 != 0", "frag", 3.2, "more-fragments flag")
        add("ip[8] = %d" % d["ttl"], "fingerprint", 5.0, "IPv4 TTL")
    elif l3 == "ipv6":
        add("ip6[7] = %d" % d["hlim"], "fingerprint", 5.0, "IPv6 hop limit")

    pl = d.get("payload")
    fmt = _payload_terms(d) if pl else None
    if fmt:
        # varkey groups the same payload field of the same service, so that
        # fields that keep changing there (counters, IDs) can be penalised
        svc = None
        if "sport" in d:
            svc = d["dport"] if _is_service_port(d["dport"], d["sport"]) else d["sport"]
        g = (l3, l4, svc)
        for k_ in range(min(16, len(pl))):
            add("%s = 0x%02x" % (fmt(k_, 1), pl[k_]), "payload", 4.0 + 0.02 * k_,
                "payload byte %d = 0x%02x (%s)" % (k_, pl[k_], dec.printable(pl[k_:k_ + 1])),
                var=(g + (k_, 1), pl[k_]))
        for off, size, c in ((0, 2, 4.1), (0, 4, 4.2), (4, 4, 4.4)):
            if len(pl) >= off + size:
                chunk = pl[off:off + size]
                what = "payload starts with" if off == 0 else "payload bytes %d-%d =" % (off, off + size - 1)
                add("%s = 0x%s" % (fmt(off, size), chunk.hex()), "payload", c,
                    "%s %s (%s)" % (what, chunk.hex(), dec.printable(chunk)), var=(g + (off, size), chunk))
    return out


def build_features(cap):
    index = collections.OrderedDict()
    meta = {}
    var_values = collections.defaultdict(set)
    var_count = collections.Counter()
    feat_vars = collections.defaultdict(set)
    for i, d in enumerate(cap.decoded):
        seen = set()
        for ctx, term, fam, cost, desc, var in packet_features(d):
            key = (ctx, term)
            if key in seen:
                continue
            seen.add(key)
            index.setdefault(key, []).append(i)
            if key not in meta or cost < meta[key][1]:
                meta[key] = (fam, cost, desc)
            if var is not None:
                var_values[var[0]].add(var[1])
                var_count[var[0]] += 1
                feat_vars[key].add(var[0])
    feats = []
    for key, positions in index.items():
        fam, cost, desc = meta[key]
        if key in feat_vars:
            # 0 = constant within its service, 1 = different in every packet
            ratios = [float(len(var_values[v]) - 1) / (var_count[v] - 1) if var_count[v] > 1 else 0.5
                      for v in feat_vars[key]]
            cost += 3.0 * max(ratios)
        feats.append(Feature(key[0], key[1], fam, cost, desc, bitset_from_indices(positions, cap.n)))
    return feats


def depth_bits(cap):
    """depth[k] = packets that have at least k VLAN tags."""
    maxd = max([len(d["vlans"]) for d in cap.decoded] or [0])
    out = []
    for k in range(maxd + 1):
        out.append(cap.bits_where(lambda i, k=k: len(cap.decoded[i]["vlans"]) >= k))
    return out


def target_specific_features(cap, targets):
    """Length bounds derived from the targets."""
    tl = [cap.pkts[i].wirelen for i in bits_to_positions(targets)]
    if not tl:
        return []
    lo, hi = min(tl), max(tl)
    lens = [p.wirelen for p in cap.pkts]
    feats = []
    if lo == hi:
        feats.append(Feature(None, "len = %d" % lo, "length", 5.0, "frame length exactly %d" % lo,
                             cap.bits_where(lambda i: lens[i] == lo)))
    if lo > min(lens):
        feats.append(Feature(None, "greater %d" % lo, "length", 5.2, "frame length >= %d" % lo,
                             cap.bits_where(lambda i: lens[i] >= lo)))
    if hi < max(lens):
        feats.append(Feature(None, "less %d" % hi, "length", 5.2, "frame length <= %d" % hi,
                             cap.bits_where(lambda i: lens[i] <= hi)))
    return feats


def needle_features(cap, targets, needle):
    """If the searched-for bytes sit at the same payload offset in every target,
    express them as payload comparisons (BPF cannot search, only compare)."""
    offs, kinds, ctxs, fmt = set(), set(), set(), None
    for i in bits_to_positions(targets):
        d = cap.decoded[i]
        pl = d.get("payload")
        if not pl or needle not in pl:
            return []
        fmt = _payload_terms(d)
        if fmt is None:
            return []
        offs.add(pl.index(needle))
        kinds.add((d["l3"], d["l4"]))
        ctxs.add(len(d["vlans"]))
    if len(offs) != 1 or len(kinds) != 1 or len(ctxs) != 1:
        return []
    off, ctx = offs.pop(), ctxs.pop()
    chunk = needle[:8]
    terms, p = [], 0
    while p < len(chunk):
        size = 4 if len(chunk) - p >= 4 else 2 if len(chunk) - p >= 2 else 1
        t = "%s = 0x%s" % (fmt(off + p, size), chunk[p:p + size].hex())
        if terms and t.startswith("ip6[6] = "):
            t = t.split(" and ", 1)[1]  # the IPv6 next-header guard is needed once
        terms.append(t)
        p += size
    term = " and ".join(terms)
    flt = compile_filter("vlan and " * ctx + term)
    bits = cap.bits_where(lambda i: len(cap.decoded[i]["vlans"]) == ctx and flt.match(cap.pkts[i]))
    return [Feature(ctx, term, "payload", 2.5, "payload has %r at offset %d" % (dec.printable(chunk), off), bits)]


def negated_features(feats, targets, negatives, depth):
    """'not X' candidates for X that rarely occurs in the targets."""
    out = []
    tcount = popcount(targets)
    for f in feats:
        if f.family not in ("host", "port", "net", "proto", "ether"):
            continue
        base = depth[f.ctx] if f.ctx else depth[0]
        nb = base & ~f.bits
        if popcount(nb & targets) * 2 < tcount or not (f.bits & negatives):
            continue
        out.append(Feature(f.ctx, f.term, f.family, f.cost + 1.5, "NOT " + f.desc, nb, neg=True))
    return out


# --------------------------------------------------------------------------
# Rule learning (sequential covering with FOIL gain)
# --------------------------------------------------------------------------

class Rule(object):
    def __init__(self, ctx, feats, bits):
        self.ctx, self.feats, self.bits = ctx, feats, bits


def _foil(p0, n0, p1, n1):
    if p1 == 0:
        return -1e9
    return p1 * (math.log(float(p1) / (p1 + n1), 2) - math.log(float(p0) / (p0 + n0), 2))


def learn_rules(feats, targets, negatives, depth, max_rules, max_terms, allow_fp):
    remaining = targets
    rules = []
    while remaining and len(rules) < max_rules:
        ctx = None
        cov = depth[0] if depth else -1
        chosen = []
        while len(chosen) < max_terms:
            p = popcount(cov & remaining)
            n = popcount(cov & negatives)
            if p == 0:
                break
            if n == 0 or (allow_fp and float(n) / (p + n) <= allow_fp):
                break
            best, best_score = None, 0.0
            for f in feats:
                if f in chosen or (f.neg and not chosen):
                    continue  # 'not X' only refines a rule, never opens one
                if ctx is not None and f.ctx is not None and f.ctx != ctx:
                    continue
                fb = cov & f.bits
                if f.ctx:
                    fb &= depth[f.ctx]
                p1 = popcount(fb & remaining)
                if p1 == 0:
                    continue
                n1 = popcount(fb & negatives)
                if n1 == n and p1 == p:
                    continue
                g = _foil(p, n, p1, n1)
                score = g * (1.0 - 0.04 * f.cost) if g > 0 else g
                if best is None or score > best_score + 1e-9 or (
                        abs(score - best_score) <= 1e-9 and f.cost < best.cost):
                    best, best_score = f, score
            if best is None or best_score <= 0:
                break
            chosen.append(best)
            cov &= best.bits
            if best.ctx is not None:
                ctx = best.ctx
                cov &= depth[ctx]
        if not chosen or not (cov & remaining):
            break
        rule = Rule(ctx or 0, chosen, cov)
        prune_rule(rule, targets, negatives, depth)
        if not (rule.bits & remaining):
            break
        rules.append(rule)
        remaining &= ~rule.bits
    return rules


def _rule_bits(feats, ctx, depth):
    b = depth[ctx] if ctx and ctx < len(depth) else (depth[0] if depth else -1)
    for f in feats:
        b &= f.bits
    return b


def prune_rule(rule, targets, negatives, depth):
    """Drop terms that do not change how many targets/others the rule selects.
    Expensive (less readable) terms are tried first."""
    for f in sorted(list(rule.feats), key=lambda f: -f.cost):
        if len(rule.feats) == 1:
            break
        rest = [x for x in rule.feats if x is not f]
        b = _rule_bits(rest, rule.ctx, depth)
        if popcount(b & negatives) <= popcount(rule.bits & negatives) and \
                popcount(b & targets) >= popcount(rule.bits & targets):
            rule.feats = rest
            rule.bits = b


# --------------------------------------------------------------------------
# Rendering (careful about libpcap's quirks: equal and/or precedence and
# 'vlan' shifting every later offset)
# --------------------------------------------------------------------------

def _render_rule(rule, hoisted=None):
    feats = [f for f in rule.feats if f is not hoisted]
    feats.sort(key=lambda f: (f.family == "payload", f.cost))
    return " and ".join(f.render() for f in feats)


def render(rules):
    """Turn rules into one expression. Rules inside VLANs are grouped under a
    single 'vlan' keyword, placed last, because every 'vlan' shifts the offsets
    of everything after it in libpcap."""
    if not rules:
        return None
    by_ctx = collections.defaultdict(list)
    for r in rules:
        by_ctx[r.ctx].append(r)
    for k in by_ctx:  # payload rules last: an out-of-range payload load rejects the packet
        by_ctx[k].sort(key=lambda r: any(f.family == "payload" for f in r.feats))
    maxctx = max(by_ctx)
    parts = [_render_rule(r) for r in by_ctx.get(0, [])]
    if maxctx >= 1:
        parts.append(_render_vlan_level(by_ctx, 1, maxctx))
    return _join_or([p for p in parts if p])


def _render_vlan_level(by_ctx, k, maxctx):
    rs = by_ctx.get(k, [])
    hoist = None
    prefix = "vlan"
    # 'vlan N' may only replace 'vlan' at the innermost level: the id test would
    # otherwise also apply to the deeper (differently tagged) rules.
    if rs and k == maxctx:
        tag_field = "ether[%d:" % (14 + 4 * (k - 1))
        vid_terms = [f.term for f in rs[0].feats if f.family == "vlan" and f.term.startswith(tag_field)]
        if vid_terms and all(any(f.term == vid_terms[0] for f in r.feats) for r in rs):
            hoist = vid_terms[0]
            prefix = "vlan %s" % hoist.rsplit("= ", 1)[1]
    parts = []
    for r in rs:
        hf = [f for f in r.feats if f.term == hoist] if hoist else []
        parts.append(_render_rule(r, hf[0] if hf else None))
    if hoist and not all(parts):
        # one rule is just "this VLAN id": 'vlan N' alone covers every rule here
        return prefix
    if k < maxctx:
        parts.append(_render_vlan_level(by_ctx, k + 1, maxctx))
    parts = [p for p in parts if p]
    if not parts:
        return prefix
    return "%s and %s" % (prefix, _wrap(_join_or(parts)))


def _wrap(s):
    """Parenthesise s if it has a top-level 'or' (and/or have equal precedence
    in libpcap, so 'vlan and a or b' would mean '(vlan and a) or b')."""
    if _has_top_level_or(s):
        return "(%s)" % s
    return s


def _has_top_level_or(s):
    depth = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and s.startswith(" or ", i):
            return True
    return False


def _balanced_outer(s):
    depth = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(s) - 1:
                return False
    return True


def _join_or(parts):
    if len(parts) == 1:
        return parts[0]
    return " or ".join("(%s)" % p if (" and " in p or " or " in p) and not _balanced_outer_paren(p) else p for p in parts)


def _balanced_outer_paren(p):
    return p.startswith("(") and p.endswith(")") and _balanced_outer(p)


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def score(cap, expr, targets, dontcare):
    flt = compile_filter(expr)
    m = cap.bits_where(lambda i: flt.match(cap.pkts[i]))
    care = cap.all & ~dontcare
    m_c = m & care
    res = {"matched": popcount(m), "bits": m}
    if targets is not None:
        tp = popcount(m_c & targets)
        fp = popcount(m_c & ~targets)
        fn = popcount(targets & ~m)
        res.update(tp=tp, fp=fp, fn=fn,
                   precision=float(tp) / (tp + fp) if tp + fp else 0.0,
                   recall=float(tp) / (tp + fn) if tp + fn else 0.0,
                   fp_bits=m_c & ~targets, fn_bits=targets & ~m)
    return res


def tcpdump_check(cap, expr, ours_bits):
    if not find_tcpdump():
        return "tcpdump not installed - verified with the built-in engine only"
    try:
        keys = tcpdump_matching_keys(cap.path, expr)
    except RuntimeError as e:
        return "tcpdump error: %s" % e
    if cap.truncated_load:
        return "tcpdump ran, but only the first %d packets were analysed - comparison skipped" % cap.n
    ours = collections.Counter((cap.pkts[i].ts_micro(), cap.pkts[i].caplen) for i in bits_to_positions(ours_bits))
    if ours == collections.Counter(keys):
        return "tcpdump agrees (%d packets)" % len(keys)
    return "WARNING: tcpdump matched %d packets, built-in engine %d - inspect with capread --compare" % (len(keys), sum(ours.values()))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_suggest(cap, args):
    targets, dontcare, desc = select_targets(cap, args)
    if targets is None:
        print("suggest needs a target (--packets/--where/--contains/--contains-hex/--flow-of)", file=sys.stderr)
        return 2
    nt = popcount(targets)
    if nt == 0:
        print("no packets match the target selection (%s)" % desc, file=sys.stderr)
        return 2
    negatives = cap.all & ~targets & ~dontcare
    print("capture : %s (%d packets%s)" % (cap.path, cap.n, ", truncated by --max-packets" if cap.truncated_load else ""))
    print("targets : %d packets - %s" % (nt, desc))
    print("others  : %d packets must NOT match%s" % (popcount(negatives), ", %d don't-care" % popcount(dontcare) if dontcare else ""))
    if nt == cap.n:
        print("\nevery packet is a target - the empty filter (or 'len > 0') already selects them.")
        return 0

    depth = depth_bits(cap)
    all_feats = build_features(cap)
    base = [f for f in all_feats if f.bits & targets]
    base += [f for f in target_specific_features(cap, targets) if f.bits & targets]
    base += negated_features(all_feats, targets, negatives, depth)
    needle = None
    if args.contains:
        needle = args.contains.encode("latin-1")
    elif args.contains_hex:
        needle = bytes(bytearray.fromhex(args.contains_hex.replace(" ", "").replace(":", "")))
    if needle:
        base += needle_features(cap, targets, needle)

    common = sorted([f for f in base if not f.neg],
                    key=lambda f: (-popcount(f.bits & targets), popcount(f.bits & negatives), f.cost))
    print("\nwhat the targets have in common (share of targets / other packets that also have it):")
    shown = 0
    for f in common:
        t = popcount(f.bits & targets)
        if float(t) / nt < 0.5 or shown >= 15:
            break
        o = popcount(f.bits & negatives)
        print("  %5.1f%%  %6d others   %-58s %s" % (100.0 * t / nt, o, "vlan and " * (f.ctx or 0) + f.render(), f.desc))
        shown += 1

    results = []
    modes = [("exact", None), ("general", GENERAL_FAMILIES)]
    if args.mode != "both":
        modes = [m for m in modes if m[0] == args.mode]
    for name, families in modes:
        feats = base if families is None else [f for f in base if f.family in families]
        rules = learn_rules(feats, targets, negatives, depth, args.max_rules, args.max_terms, args.allow_fp)
        expr = render(rules)
        if not expr:
            results.append((name, None, None, rules))
            continue
        try:
            res = score(cap, expr, targets, dontcare)
        except (FilterSyntaxError, FilterUnsupported) as e:
            results.append((name, expr, {"error": str(e)}, rules))
            continue
        results.append((name, expr, res, rules))

    printed = set()
    print("\nsuggested filters:")
    out_json = []
    for name, expr, res, rules in results:
        if expr is None:
            print("\n  [%s] no filter found with these feature families" % name)
            continue
        if expr in printed:
            print("\n  [%s] same as above" % name)
            continue
        printed.add(expr)
        print("\n  [%s]  %s" % (name, expr))
        if "error" in res:
            print("      engine error: %s" % res["error"])
            continue
        print("      selects %d packets: %d/%d targets (recall %.0f%%), %d other packets (precision %.0f%%)"
              % (res["matched"], res["tp"], nt, 100 * res["recall"], res["fp"], 100 * res["precision"]))
        for r in rules:
            tp = popcount(r.bits & targets)
            fp = popcount(r.bits & negatives)
            print("      - rule covering %d targets / %d others:" % (tp, fp))
            if r.ctx:
                print("          %-60s %s" % ("vlan" + " and vlan" * (r.ctx - 1), "inside %d VLAN tag(s)" % r.ctx))
            for f in sorted(r.feats, key=lambda f: (f.family == "payload", f.cost)):
                print("          %-60s %s" % (f.render(), f.desc))
        if res["fn"]:
            print("      missed targets: %s" % _fmt_idx(cap, res["fn_bits"]))
        if res["fp"]:
            print("      extra packets : %s" % _fmt_idx(cap, res["fp_bits"]))
        if not args.no_tcpdump:
            print("      %s" % tcpdump_check(cap, expr, res["bits"]))
        out_json.append({"mode": name, "filter": expr, "matched": res["matched"], "tp": res["tp"],
                         "fp": res["fp"], "fn": res["fn"]})
    if args.json:
        print(json.dumps(out_json, indent=2))
    print("\nnext: python3 tools/capread.py %s '<filter>'   # eyeball the matches" % cap.path)
    if find_tcpdump():
        lt = LINKTYPE_TO_DLT_NAME.get(next(iter(cap.linktypes)), "EN10MB") if cap.linktypes else "EN10MB"
        best = [e for _n, e, r, _ in results if e and r and "error" not in r]
        if best and args.bytecode:
            print("\nclassic BPF bytecode for '%s':\n%s" % (best[0], tcpdump_compile(best[0], lt)))
    return 0


def _fmt_idx(cap, bits, limit=30):
    pos = bits_to_positions(bits)
    s = ",".join(str(cap.pkts[i].index) for i in pos[:limit])
    return s + (" ... (+%d)" % (len(pos) - limit) if len(pos) > limit else "")


def cmd_test(cap, args):
    targets, dontcare, desc = select_targets(cap, args)
    try:
        res = score(cap, args.filter, targets, dontcare)
    except (FilterSyntaxError, FilterUnsupported) as e:
        print("filter error: %s" % e, file=sys.stderr)
        return 2
    print("filter  : %s" % args.filter)
    print("matches : %d of %d packets" % (res["matched"], cap.n))
    if targets is not None:
        nt = popcount(targets)
        print("targets : %d packets - %s" % (nt, desc))
        print("TP %d  FP %d  FN %d   precision %.1f%%  recall %.1f%%" % (
            res["tp"], res["fp"], res["fn"], 100 * res["precision"], 100 * res["recall"]))
        for label, key in (("false positives (matched, not wanted)", "fp_bits"),
                           ("false negatives (wanted, not matched)", "fn_bits")):
            pos = bits_to_positions(res[key])
            if pos:
                print("\n%s:" % label)
                for i in pos[:args.show]:
                    print("  #%-6d %s" % (cap.pkts[i].index, dec.summary(cap.decoded[i])))
                if len(pos) > args.show:
                    print("  ... %d more" % (len(pos) - args.show))
    else:
        for i in bits_to_positions(res["bits"])[:args.show]:
            print("  #%-6d %s" % (cap.pkts[i].index, dec.summary(cap.decoded[i])))
    if not args.no_tcpdump:
        print("\n%s" % tcpdump_check(cap, args.filter, res["bits"]))
    return 0


def cmd_profile(cap, args):
    D = cap.decoded
    top = args.top
    print("capture : %s" % cap.path)
    print("packets : %d%s" % (cap.n, " (truncated by --max-packets)" if cap.truncated_load else ""))
    print("link    : %s" % ", ".join("%d x%d" % (k, v) for k, v in cap.linktypes.items()))

    def section(title, counter, bpf_of, n=top):
        if not counter:
            return
        print("\n%s" % title)
        for key, cnt in counter.most_common(n):
            label, bpf = bpf_of(key)
            print("  %6d  %-46s bpf: %s" % (cnt, label, bpf))

    vpre = lambda d: "vlan and " * len(d["vlans"])

    proto = collections.Counter()
    for d in D:
        l3, l4 = d.get("l3"), d.get("l4")
        if l3 in ("ipv4", "ipv6"):
            key = (len(d["vlans"]) > 0, "ip" if l3 == "ipv4" else "ip6",
                   l4 if not d.get("frag_off") else "fragment")
        elif l3 == "arp":
            key = (len(d["vlans"]) > 0, "arp", None)
        else:
            et = d.get("ethertype")
            key = (len(d["vlans"]) > 0, "ether proto 0x%04x" % et if isinstance(et, int) and et > 1500 else "other", None)
        proto[key] += 1

    def proto_bpf(k):
        vl, l3, l4 = k
        pre = "vlan and " if vl else ""
        label = ("vlan/" if vl else "") + l3 + ("/" + l4 if l4 else "")
        if l4 == "fragment":
            return label, pre + "%s and ip[6:2] & 0x1fff != 0" % l3
        if l4 in ("icmp", "icmp6", "igmp"):
            return label, pre + l4
        if l4 in ("tcp", "udp", "sctp"):
            return label, pre + "%s and %s" % (l3, l4)  # bare 'tcp' would match IPv4 and IPv6
        return label, pre + l3
    section("protocols", proto, proto_bpf)

    hosts = collections.Counter()
    convs = collections.Counter()
    sports = collections.Counter()
    flags = collections.Counter()
    icmp = collections.Counter()
    vlans = collections.Counter()
    macs = collections.Counter()
    dns = collections.Counter()
    http = collections.Counter()
    sni = collections.Counter()
    modbus = collections.Counter()
    syns = collections.defaultdict(set)
    prefixes = collections.Counter()
    for d in D:
        pre = vpre(d)
        if d.get("src"):
            hosts[(pre, d["src"])] += 1
            hosts[(pre, d["dst"])] += 1
            a, b = sorted([d["src"], d["dst"]])
            convs[(pre, a, b, d.get("l4") if d.get("l3") != "arp" else "arp")] += 1
        if d.get("l4") in ("tcp", "udp") and "sport" in d:
            sp, dp = d["sport"], d["dport"]
            svc = dp if _is_service_port(dp, sp) else sp
            sports[(pre, d["l4"], svc)] += 1
            if d["l4"] == "tcp" and d["flags"] & 0x12 == 0x02:
                syns[(pre, d["src"], d["dst"])].add(dp)
            pl = d.get("payload") or b""
            if len(pl) >= 4:
                prefixes[(pre, d["l4"], d["l3"], svc, pl[:4])] += 1
        if d.get("l4") == "tcp" and d.get("l3") == "ipv4" and "flags" in d:
            flags[(pre, d["flags"])] += 1
        if d.get("l4") in ("icmp", "icmp6"):
            icmp[(pre, d["l4"], d["icmp_type"])] += 1
        for v in d["vlans"][:1]:
            vlans[v] += 1
        if "eth_src" in d:
            macs[d["eth_src"]] += 1
        if d.get("dns_qname") and d.get("dns_qr") == "query":
            dns[d["dns_qname"]] += 1
        if d.get("http"):
            http[(d["http"].split(" HTTP/")[0][:60], d.get("http_host", ""))] += 1
        if d.get("tls_sni"):
            sni[(pre, d["tls_sni"])] += 1
        if "modbus_func" in d:
            modbus[(pre, d["modbus_func"])] += 1

    section("top hosts", hosts, lambda k: (k[1], k[0] + "host %s" % k[1]))
    section("top conversations", convs, lambda k: ("%s <-> %s %s" % (k[1], k[2], k[3] or ""),
                                                    k[0] + "host %s and host %s%s" % (k[1], k[2], " and %s" % k[3] if k[3] in ("tcp", "udp", "icmp", "arp") else "")))
    section("services (server-side port)", sports, lambda k: ("%s/%d" % (k[1], k[2]), k[0] + "%s port %d" % (k[1], k[2])))
    section("VLANs", vlans, lambda v: ("vlan %d" % v, "vlan %d" % v))
    section("TCP flag combinations (IPv4)", flags, lambda k: ("[%s]" % dec.flags_str(k[1]), k[0] + "tcp[tcpflags] = 0x%02x" % k[1]))
    section("ICMP types", icmp, lambda k: ("%s type %d (%s)" % (k[1], k[2], (dec.ICMP_TYPES if k[1] == "icmp" else dec.ICMP6_TYPES).get(k[2], "?")),
                                           k[0] + ("icmp[icmptype] = %d" % k[2] if k[1] == "icmp" else "ip6[6] = 58 and ip6[40] = %d" % k[2])))
    section("source MAC addresses", macs, lambda m: (m, "ether src %s" % m))
    section("payload prefixes (first 4 bytes)", prefixes, lambda k: (
        "%s/%d %s %r" % (k[1], k[3], k[4].hex(), dec.printable(k[4])),
        k[0] + _prefix_bpf(k[1], k[2], k[3], k[4])))
    if dns:
        print("\nDNS names queried (BPF cannot match a name at a variable offset; filter the DNS server/port and use capread to look)")
        for name, cnt in dns.most_common(top):
            print("  %6d  %s" % (cnt, name))
    if http:
        print("\nHTTP request/response lines")
        for (line, host), cnt in http.most_common(top):
            print("  %6d  %-50s host=%s" % (cnt, line, host))
        print("  bpf for any HTTP GET (IPv4): %s = 0x47455420" % (TCP_PAYLOAD % ("", ":4")))
    section("TLS SNI (BPF cannot match the name itself; the bpf selects TLS ClientHellos)", sni, lambda k: (k[1], k[0] + "tcp port 443 and %s = 0x16 and %s = 0x01" % (
        TCP_PAYLOAD % ("", ""), TCP_PAYLOAD % (" + 5", ""))))
    section("Modbus/TCP function codes", modbus, lambda k: (
        "func %d (%s)" % (k[1], dec.MODBUS_FUNCS.get(k[1] & 0x7F, "?")),
        k[0] + "tcp port 502 and %s = %d" % (TCP_PAYLOAD % (" + 7", ""), k[1])))

    scans = [(k, ports) for k, ports in syns.items() if len(ports) >= args.scan_ports]
    if scans:
        print("\npossible port scans (one source sending SYNs to >= %d ports of one target)" % args.scan_ports)
        for (pre, s, t), ports in sorted(scans, key=lambda x: -len(x[1]))[:top]:
            print("  %s -> %s: %d ports (%s)" % (s, t, len(ports), ",".join(map(str, sorted(ports)[:12]))))
            print("      scan probes : %ssrc host %s and dst host %s and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn" % (pre, s, t))
            print("      all traffic : %shost %s and host %s" % (pre, s, t))
    frags = sum(1 for d in D if d.get("frag_off") or d.get("mf"))
    if frags:
        print("\nIPv4/IPv6 fragments: %d packets   bpf (IPv4): ip[6:2] & 0x3fff != 0" % frags)
    bc = sum(1 for d in D if d.get("eth_dst") == "ff:ff:ff:ff:ff:ff")
    if bc:
        print("Ethernet broadcasts: %d packets   bpf: ether broadcast" % bc)
    print("\nnext: bpfgen.py suggest %s --packets <numbers> | --where '<bpf>' | --contains <text>" % cap.path)
    return 0


def _prefix_bpf(l4, l3, port, pfx):
    if l3 == "ipv4" and l4 == "tcp":
        return "tcp port %d and %s = 0x%s" % (port, TCP_PAYLOAD % ("", ":4"), pfx.hex())
    if l3 == "ipv4" and l4 == "udp":
        return "udp port %d and udp[8:4] = 0x%s" % (port, pfx.hex())
    if l3 == "ipv6" and l4 == "tcp":
        return "tcp port %d and ip6[6] = 6 and %s = 0x%s" % (port, IP6_TCP_PAYLOAD % ("", ":4"), pfx.hex())
    return "udp port %d and ip6[6] = 17 and ip6[48:4] = 0x%s" % (port, pfx.hex())


def build_argparser():
    ap = argparse.ArgumentParser(prog="bpfgen", description="Find patterns in a capture and generate BPF filters.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Examples:" + __doc__.split("Examples:", 1)[1])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("profile", help="summarise the capture with a BPF for every notable group")
    p.add_argument("file")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--scan-ports", type=int, default=5, help="distinct SYN ports that count as a scan")
    p.add_argument("--max-packets", type=int, default=500000)

    s = sub.add_parser("suggest", help="learn a BPF that selects the target packets")
    s.add_argument("file")
    add_target_args(s)
    s.add_argument("--mode", choices=("both", "exact", "general"), default="both",
                   help="exact: may use payload bytes/lengths/TTL; general: protocol/address/port terms only")
    s.add_argument("--max-rules", type=int, default=6, help="max OR-ed alternatives")
    s.add_argument("--max-terms", type=int, default=6, help="max AND-ed terms per alternative")
    s.add_argument("--allow-fp", type=float, default=0.0,
                   help="stop refining a rule once its false-positive share is below this (0-1)")
    s.add_argument("--max-packets", type=int, default=200000)
    s.add_argument("--json", action="store_true")
    s.add_argument("--bytecode", action="store_true", help="print tcpdump -d output for the first suggestion")
    s.add_argument("--no-tcpdump", action="store_true", help="skip the tcpdump cross-check")

    t = sub.add_parser("test", help="score a filter against the capture (and optional targets)")
    t.add_argument("file")
    t.add_argument("filter")
    add_target_args(t)
    t.add_argument("--show", type=int, default=20)
    t.add_argument("--max-packets", type=int, default=500000)
    t.add_argument("--no-tcpdump", action="store_true")
    return ap


def main(argv=None):
    try:
        return _main(argv)
    except BrokenPipeError:  # e.g. piped into head
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


def _main(argv=None):
    ap = build_argparser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        cap = Capture(args.file, args.max_packets)
    except CaptureFormatError as e:
        print("capture error: %s" % e, file=sys.stderr)
        return 3
    if cap.n == 0:
        print("capture is empty", file=sys.stderr)
        return 3
    try:
        if args.cmd == "profile":
            return cmd_profile(cap, args)
        if args.cmd == "suggest":
            return cmd_suggest(cap, args)
        return cmd_test(cap, args)
    except (FilterSyntaxError, FilterUnsupported) as e:
        print("filter error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
