"""Compare the bpfkit filter engine with real tcpdump/libpcap on real captures.

  corpus.py xcheck FILE_OR_DIR... [--tcpdump CMD] [--tmpdir DIR]
      Run every filter on every capture through bpfkit and through tcpdump
      and report each difference. Needs tcpdump. CMD can be a prefix such as
      "docker exec old-pcap tcpdump" to test another libpcap version; the
      captures and --tmpdir must be visible at the same path there.

  corpus.py record [--tcpdump CMD]
      Run tcpdump over tests/corpus/*.pcap* and store its answers in
      tests/corpus/expected.json (a count and digest of the packet numbers
      per filter).

  corpus.py check
      Verify bpfkit against tests/corpus/expected.json. No tcpdump needed;
      selftest runs this step.

Every capture gets a generic filter set, plus filters derived from its own
contents: its busiest hosts, ports, nets, MACs and VLAN ids.
"""

import argparse
import collections
import glob
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile

from . import decode as dec
from .bpf import compile_filter, FilterSyntaxError, FilterUnsupported
from .pcapio import read_packets, SUPPORTED_LINKTYPES, CaptureFormatError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(ROOT, "tests", "corpus")
EXPECTED = os.path.join(CORPUS_DIR, "expected.json")

# Filters that make sense on any IP capture (no addresses).
GENERIC = [
    "ip", "ip6", "arp", "tcp", "udp", "icmp", "icmp6", "sctp", "igmp", "pim",
    "ip proto 47", "ip6 proto 17", "proto 50", "esp", "ah",
    "tcp port 80", "port 53", "udp port 53", "tcp port 443", "port 123 or port 161",
    "tcp portrange 1-1023", "udp portrange 1024-65535", "src port 53", "dst portrange 0-1023",
    "tcp[tcpflags] & tcp-syn != 0", "tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn",
    "tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)", "tcp[tcpflags] & tcp-rst != 0",
    "tcp[tcpflags] & tcp-fin != 0", "tcp[tcpflags] = 0x18", "tcp[tcpflags] & (tcp-ece|tcp-cwr) != 0",
    "tcp[12] & 0xf0 > 0x50", "tcp[14:2] = 0",
    "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420",
    "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450",
    "tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16 and tcp[((tcp[12:1] & 0xf0) >> 2) + 5] = 1",
    "tcp and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0) >> 2)) != 0)",
    "udp[8] = 0", "udp[4:2] > 100", "udp port 53 and udp[10] & 0x80 = 0", "udp port 53 and udp[11] & 0x0f != 0",
    "icmp[icmptype] = icmp-echo", "icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply",
    "icmp[icmptype] = icmp-unreach and icmp[icmpcode] = 3",
    "ip6[6] = 58 and ip6[40] >= 133 and ip6[40] <= 137", "ip6[6] = 6 and ip6[53] & 0x02 != 0",
    "ip6[6] = 0 or ip6[6] = 43 or ip6[6] = 44 or ip6[6] = 60",
    "ip[6:2] & 0x3fff != 0", "ip[6:2] & 0x1fff != 0", "ip[6] & 0x40 != 0", "ip[0] & 0x0f > 5",
    "ip[8] < 5", "ip[1] & 0xfc != 0", "ip multicast", "ip6 multicast", "ip broadcast",
    "ip and ip[12:4] = ip[16:4]", "ip[2:2] > 576",
    "len > 1000", "less 64", "greater 200", "len >= 60 and len <= 100",
    "not ip and not ip6", "tcp or udp and not port 53", "(tcp or udp) and not port 53",
    "not (tcp port 80 or tcp port 443)", "ip and not tcp and not udp and not icmp",
    "tcp[100] = 0 or udp",
]
# Only meaningful when the capture is Ethernet.
ETHER = [
    "ether broadcast", "ether multicast", "not ether broadcast and not ether multicast",
    "ether proto 0x88cc", "ether proto 0x8100", "ether[12:2] = 0x8100", "ether[0] & 1 = 1",
    "vlan", "vlan and ip", "vlan and vlan", "ip or (vlan and ip)", "(vlan and ip) or ip",
    "vlan and tcp port 80", "vlan and udp", "ip or vlan", "not vlan and ip",
]
LT_NAMES = {0: "NULL", 1: "EN10MB", 101: "RAW", 108: "LOOP", 113: "LINUX_SLL",
            228: "IPV4", 229: "IPV6", 276: "LINUX_SLL2"}

# libpcap behaviour bpfkit intentionally does not copy: the optimiser can skip an
# out-of-range load when the result is already decided (knowledge/bpf/04-gotchas.md §6).
KNOWN_DIFFERENCES = ("tcp[100] = 0 or udp",)


def derived_filters(pkts, linktype):
    """Address/port/VLAN filters built from what is actually in the capture."""
    hosts4, hosts6, ports, macs, vlans = (collections.Counter() for _ in range(5))
    for p in pkts:
        d = dec.decode(p)
        for k in ("src", "dst"):
            a = d.get(k)
            if a:
                (hosts6 if ":" in a else hosts4)[a] += 1
        for k in ("sport", "dport"):
            if d.get(k) is not None:
                ports[(d.get("l4"), d[k])] += 1
        if d.get("eth_src"):
            macs[d["eth_src"]] += 1
        for v in d["vlans"]:
            vlans[v] += 1
    out = []
    for a, _ in hosts4.most_common(2):
        out += ["host %s" % a, "src host %s" % a, "dst host %s or arp" % a, "ip host %s" % a,
                "net %s.0/24" % a.rsplit(".", 1)[0], "not net %s.0.0/16" % ".".join(a.split(".")[:2])]
    for a, _ in hosts6.most_common(2):
        out += ["host %s" % a, "ip6 src host %s" % a]
    for (l4, port), _ in ports.most_common(3):
        out += ["port %d" % port,
                "%s dst port %d" % (l4, port) if l4 in ("tcp", "udp", "sctp") else "src port %d" % port,
                "host %s and port %d" % (hosts4.most_common(1)[0][0], port) if hosts4 else "src port %d" % port]
    if linktype == 1:
        for m, _ in macs.most_common(2):
            out += ["ether host %s" % m, "ether src %s and not ip" % m]
        for v, _ in vlans.most_common(2):
            out += ["vlan %d" % v, "vlan %d and ip" % v, "vlan %d or ip" % v]
    seen, res = set(), []
    for f in out:
        if f not in seen:
            seen.add(f)
            res.append(f)
    return res


def filters_for(pkts, linktype):
    fl = list(GENERIC)
    if linktype == 1:
        fl += ETHER
    return fl + derived_filters(pkts, linktype)


def ours(pkts, expr):
    flt = compile_filter(expr)
    return [p.index for p in pkts if flt.match(p)]


def theirs(tcpdump, path, expr, pkts, tmpdir):
    """Packet numbers tcpdump selects, or 'error: ...'."""
    fd, tmp = tempfile.mkstemp(suffix=".pcap", dir=tmpdir)
    os.close(fd)
    try:
        r = subprocess.run(tcpdump + ["-r", path, "-w", tmp, expr], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        if r.returncode != 0:
            msg = r.stderr.strip().splitlines()
            return "error: " + (msg[-1] if msg else "exit %d" % r.returncode)
        # Map tcpdump's output back to packet numbers. tcpdump -w may truncate
        # packets to the file's snaplen, and timestamps beyond 32-bit seconds
        # don't survive it, so match on timestamp + wire length + a common data
        # prefix, falling back to wire length + data.
        index = collections.defaultdict(list)
        by_len = collections.defaultdict(list)
        for p in pkts:
            index[(p.ts_micro(), p.wirelen)].append(p)
            by_len[p.wirelen].append(p)
        out = []
        for q in read_packets(tmp):
            cands = index.get((q.ts_micro(), q.wirelen)) or [p for p in by_len.get(q.wirelen, [])
                                                              if p.index not in out]
            for i, p in enumerate(cands):
                n = min(len(p.data), len(q.data))
                if p.data[:n] == q.data[:n]:
                    out.append(p.index)
                    cands.pop(i)
                    break
            else:
                out.append(-1)
        return sorted(out)
    finally:
        os.unlink(tmp)


def digest(indices):
    return hashlib.sha1(",".join(map(str, indices)).encode()).hexdigest()[:16]


def load(path):
    try:
        pkts = list(read_packets(path))
    except (CaptureFormatError, OSError) as e:
        return None, str(e)
    lts = set(p.linktype for p in pkts)
    if not pkts or len(lts) != 1 or next(iter(lts)) not in SUPPORTED_LINKTYPES:
        return None, "link type(s) %s not supported by the engine" % sorted(lts)
    return pkts, None


def expand(paths):
    out = []
    for p in map(os.path.abspath, paths):  # absolute: the tcpdump command may run elsewhere (docker)
        if os.path.isdir(p):
            out += sorted(f for f in glob.glob(os.path.join(p, "*"))
                          if f.endswith((".pcap", ".pcapng", ".cap", ".pcap.gz")))
        else:
            out.append(p)
    return out


def tcpdump_version(tcpdump):
    try:
        r = subprocess.run(tcpdump + ["--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=60)
    except OSError as e:
        return "unavailable (%s)" % e
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    return " / ".join(lines[:2])


def cmd_xcheck(args):
    tcpdump = shlex.split(args.tcpdump)
    tmpdir = args.tmpdir or tempfile.mkdtemp(prefix="corpus-")
    print("tcpdump: %s" % tcpdump_version(tcpdump))
    stats = collections.Counter()
    problems = []
    for path in expand(args.paths):
        pkts, why = load(path)
        if pkts is None:
            stats["skipped files"] += 1
            continue
        stats["files"] += 1
        stats["packets"] += len(pkts)
        lt = pkts[0].linktype
        for expr in filters_for(pkts, lt):
            try:
                a = ours(pkts, expr)
            except (FilterSyntaxError, FilterUnsupported) as e:
                a = "error: %s" % e
            b = theirs(tcpdump, path, expr, pkts, tmpdir)
            stats["comparisons"] += 1
            if isinstance(b, str) and "rejects all packets" in b:
                b = []  # libpcap refuses filters that can never match; bpfkit returns nothing
            if isinstance(a, str) and isinstance(b, str):
                stats["both rejected"] += 1
                continue
            if a == b:
                stats["agree"] += 1
                continue
            if expr in KNOWN_DIFFERENCES:
                stats["known differences"] += 1
                continue
            stats["MISMATCH"] += 1
            problems.append((os.path.basename(path), LT_NAMES.get(lt, lt), expr, a, b))

    def fmt(x):
        return x if isinstance(x, str) else "%d pkts %s" % (len(x), x[:12])
    for name, lt, expr, a, b in problems[:args.show]:
        print("MISMATCH %s [%s] %r\n   bpfkit : %s\n   tcpdump: %s" % (name, lt, expr, fmt(a), fmt(b)))
    print("\n" + ", ".join("%s=%d" % kv for kv in sorted(stats.items())))
    return 1 if problems else 0


def corpus_files():
    return sorted(f for f in glob.glob(os.path.join(CORPUS_DIR, "*"))
                  if f.endswith((".pcap", ".pcapng", ".pcap.gz")))


def cmd_record(args):
    tcpdump = shlex.split(args.tcpdump)
    tmpdir = tempfile.mkdtemp(prefix="corpus-")
    out = {"generated_by": tcpdump_version(tcpdump), "captures": {}}
    for path in corpus_files():
        pkts, why = load(path)
        if pkts is None:
            print("skip %s: %s" % (path, why))
            continue
        name = os.path.basename(path)
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        res = {}
        for expr in filters_for(pkts, pkts[0].linktype):
            if expr in KNOWN_DIFFERENCES:
                continue
            b = theirs(tcpdump, path, expr, pkts, tmpdir)
            if isinstance(b, str):
                if "rejects all packets" in b:
                    b = []
                else:
                    res[expr] = {"error": b}
                    continue
            res[expr] = {"count": len(b), "digest": digest(b)}
        out["captures"][name] = {"sha256": sha, "packets": len(pkts), "filters": res}
        print("%-40s %4d packets %3d filters" % (name, len(pkts), len(res)))
    with open(EXPECTED, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote %s" % EXPECTED)
    return 0


def check_corpus(verbose=True):
    """Return (checks run, list of problems). Used by selftest."""
    if not os.path.exists(EXPECTED):
        return 0, ["%s missing" % EXPECTED]
    with open(EXPECTED) as f:
        exp = json.load(f)
    checked, problems = 0, []
    for name, info in sorted(exp["captures"].items()):
        path = os.path.join(CORPUS_DIR, name)
        if not os.path.exists(path):
            problems.append("%s: capture missing" % name)
            continue
        with open(path, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != info["sha256"]:
                problems.append("%s: file changed (sha256 mismatch); re-run corpus.py record" % name)
                continue
        pkts, why = load(path)
        if pkts is None:
            problems.append("%s: %s" % (name, why))
            continue
        for expr, want in sorted(info["filters"].items()):
            checked += 1
            try:
                got = ours(pkts, expr)
            except (FilterSyntaxError, FilterUnsupported) as e:
                if "error" not in want:
                    problems.append("%s: %r -> bpfkit error %s" % (name, expr, e))
                continue
            if "error" in want:
                problems.append("%s: %r -> tcpdump rejected it (%s) but bpfkit accepted"
                                % (name, expr, want["error"]))
            elif (len(got), digest(got)) != (want["count"], want["digest"]):
                problems.append("%s: %r -> bpfkit %d packets, tcpdump %d" % (name, expr, len(got), want["count"]))
    if verbose:
        for p in problems:
            print("  FAIL " + p)
    return checked, problems


def main(argv=None):
    ap = argparse.ArgumentParser(prog="corpus", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    x = sub.add_parser("xcheck", help="compare bpfkit with tcpdump on captures")
    x.add_argument("paths", nargs="+")
    x.add_argument("--tcpdump", default="tcpdump", help="tcpdump command (may be a docker exec prefix)")
    x.add_argument("--tmpdir", help="temp dir visible to the tcpdump command (for docker)")
    x.add_argument("--show", type=int, default=40)
    r = sub.add_parser("record", help="regenerate tests/corpus/expected.json with tcpdump")
    r.add_argument("--tcpdump", default="tcpdump")
    sub.add_parser("check", help="verify bpfkit against tests/corpus/expected.json")
    args = ap.parse_args(argv)
    if args.cmd == "xcheck":
        return cmd_xcheck(args)
    if args.cmd == "record":
        return cmd_record(args)
    if args.cmd == "check":
        checked, problems = check_corpus()
        print("%d corpus checks, %d problems" % (checked, len(problems)))
        return 1 if problems else 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
