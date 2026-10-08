"""capread - read .cap/.pcap/.pcapng files and filter them with a BPF expression.

Pure Python standard library; works offline / air-gapped.

Examples:
  capread.py traffic.cap                                 # list every packet
  capread.py traffic.cap 'tcp port 443 and host 10.0.0.5'
  capread.py traffic.cap -F filter.bpf -v                # filter from file, field dump
  capread.py traffic.cap 'udp port 53' --stats           # counts + breakdown only
  capread.py traffic.cap 'icmp' -w icmp_only.pcap        # save matches
  capread.py traffic.cap --info                          # capinfos-like summary
  capread.py traffic.cap 'vlan and ip' --check           # validate the filter only
  capread.py traffic.cap 'tcp[13]=2' --compare           # cross-check against tcpdump
"""

import argparse
import collections
import json
import sys

from . import decode as dec
from .bpf import compile_filter, FilterSyntaxError, FilterUnsupported
from .pcapio import read_packets, detect_format, linktype_name, PcapWriter, CaptureFormatError
from .util import (parse_index_spec, find_tcpdump, tcpdump_compile,
                   tcpdump_matching_keys, LINKTYPE_TO_DLT_NAME)


def build_argparser():
    ap = argparse.ArgumentParser(
        prog="capread",
        description="Read a capture file (.cap/.pcap/.pcapng/snoop, optionally .gz) "
                    "and show the packets that match a BPF (tcpdump) filter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:" + __doc__.split("Examples:", 1)[1])
    ap.add_argument("file", help="capture file")
    ap.add_argument("filter", nargs="*", help="BPF filter expression (quote it; words are joined like tcpdump)")
    ap.add_argument("-F", dest="filter_file", help="read the filter expression from a file ('#' comments allowed)")
    ap.add_argument("-c", "--count", type=int, help="stop after printing this many matching packets")
    ap.add_argument("--packets", help="only consider these packet numbers, e.g. '1-50,77'")
    ap.add_argument("-v", "--verbose", action="store_true", help="dump decoded header fields")
    ap.add_argument("-x", "--hex", action="store_true", help="hex dump each matching packet")
    ap.add_argument("--json", action="store_true", help="emit one JSON object per matching packet")
    ap.add_argument("--abs-time", action="store_true", help="print full UTC date-time stamps")
    ap.add_argument("--stats", action="store_true", help="print only match counts and a traffic breakdown")
    ap.add_argument("--info", action="store_true", help="print capture file information and exit")
    ap.add_argument("-w", dest="write", help="write matching packets to this pcap file")
    ap.add_argument("--check", action="store_true",
                    help="only validate the filter (and show tcpdump -d bytecode if tcpdump exists)")
    ap.add_argument("--compare", action="store_true",
                    help="also run the filter through tcpdump (if installed) and compare results")
    return ap


def load_filter_text(args):
    if args.filter_file:
        with open(args.filter_file) as f:
            lines = [ln.split("#", 1)[0] for ln in f]
        return " ".join(" ".join(lines).split())
    return " ".join(args.filter)


def main(argv=None):
    try:
        return _main(argv)
    except BrokenPipeError:  # e.g. piped into head
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


def _main(argv=None):
    args = build_argparser().parse_args(argv)
    expr = load_filter_text(args)
    try:
        flt = compile_filter(expr)
    except (FilterSyntaxError, FilterUnsupported) as e:
        print("filter error: %s" % e, file=sys.stderr)
        return 2

    if args.check:
        print("filter OK: %s" % (expr or "(empty: matches everything)"))
        print("parsed as: %s" % flt)
        lt = _first_linktype(args.file)
        bc = tcpdump_compile(expr, LINKTYPE_TO_DLT_NAME.get(lt, "EN10MB")) if expr else None
        if bc:
            print("\ntcpdump -d (classic BPF bytecode, link type %s):\n%s" % (LINKTYPE_TO_DLT_NAME.get(lt, "EN10MB"), bc))
        return 0

    if args.info:
        return print_info(args.file)

    only = parse_index_spec(args.packets) if args.packets else None
    writer = None
    shown = matched = total = 0
    stats = Stats() if args.stats else None
    matched_keys = []
    limited = False
    try:
        for pkt in read_packets(args.file):
            total += 1
            if only is not None and pkt.index not in only:
                continue
            try:
                ok = flt.match(pkt)
            except FilterUnsupported as e:
                print("filter error on packet #%d: %s" % (pkt.index, e), file=sys.stderr)
                return 2
            if not ok:
                continue
            if (args.count is not None and shown >= args.count and stats is None
                    and not args.write and not args.compare):
                limited = True
                break
            matched += 1
            if args.compare:
                matched_keys.append((pkt.ts_micro(), pkt.caplen, pkt.index))
            if args.write:
                if writer is None:
                    writer = PcapWriter(args.write, pkt.linktype)
                writer.write(pkt)
            if stats is not None:
                stats.add(dec.decode(pkt))
                continue
            if args.count is not None and shown >= args.count:
                continue
            shown += 1
            print_packet(pkt, args)
    except CaptureFormatError as e:
        print("capture error: %s" % e, file=sys.stderr)
        return 3
    finally:
        if writer is not None:
            writer.close()

    if stats is not None:
        stats.report(expr, matched, total)
    elif not args.json:
        if limited:
            print("-- stopped after %d matching packet(s) (-c); filter: %s" % (shown, expr or "(none)"), file=sys.stderr)
        else:
            print("-- %d of %d packet(s) matched; filter: %s" % (matched, total, expr or "(none)"), file=sys.stderr)
    if args.write:
        print("-- wrote %d packet(s) to %s" % (matched, args.write), file=sys.stderr)
    if args.compare:
        return compare_with_tcpdump(args.file, expr, matched_keys, only)
    return 0


def _first_linktype(path):
    try:
        for p in read_packets(path):
            return p.linktype
    except (CaptureFormatError, OSError):
        pass
    return 1


def print_packet(pkt, args):
    d = dec.decode(pkt)
    if args.json:
        j = dec.to_jsonable(d)
        j["ts"] = "%d.%06d" % pkt.ts_micro()
        print(json.dumps(j, sort_keys=True))
        return
    print("#%-6d %s  %s" % (pkt.index, dec.fmt_ts(pkt, args.abs_time), dec.summary(d)))
    if args.verbose:
        for ln in dec.verbose_lines(d):
            print(ln)
    if args.hex:
        for ln in dec.hexdump(pkt.data):
            print(ln)


class Stats(object):
    def __init__(self):
        self.proto = collections.Counter()
        self.hosts = collections.Counter()
        self.convs = collections.Counter()
        self.ports = collections.Counter()
        self.vlans = collections.Counter()
        self.bytes = 0
        self.first = self.last = None

    def add(self, d):
        self.bytes += d["len"]
        label = d.get("l4") or d.get("l3") or "other"
        if d.get("l3") in ("ipv4", "ipv6") and d.get("l4"):
            label = "%s/%s" % (d["l3"], d["l4"])
        self.proto[label] += 1
        for v in d["vlans"]:
            self.vlans[v] += 1
        if d.get("src"):
            self.hosts[d["src"]] += 1
            self.hosts[d["dst"]] += 1
            a, b = sorted([dec.endpoint(d, "src"), dec.endpoint(d, "dst")])
            self.convs["%s <-> %s (%s)" % (a, b, d.get("l4") or d.get("l3"))] += 1
        if d.get("l4") in ("tcp", "udp"):
            self.ports["%s/%d" % (d["l4"], min(d["sport"], d["dport"]))] += 1

    def report(self, expr, matched, total):
        print("filter      : %s" % (expr or "(none)"))
        print("matched     : %d of %d packets (%.1f%%), %d bytes on the wire" % (
            matched, total, 100.0 * matched / total if total else 0, self.bytes))
        for title, c in (("protocols", self.proto), ("top hosts", self.hosts),
                         ("top conversations", self.convs),
                         ("top service ports (lower port of each packet)", self.ports),
                         ("vlan ids", self.vlans)):
            if not c:
                continue
            print("\n%s:" % title)
            for k, v in c.most_common(10):
                print("  %7d  %s" % (v, k))


def print_info(path):
    fmt = detect_format(path)
    n = 0
    lts = collections.Counter()
    first = last = None
    total_bytes = cap_bytes = 0
    smin, smax = None, 0
    truncated = 0
    try:
        for p in read_packets(path):
            n += 1
            lts[p.linktype] += 1
            t = p.ts
            first = t if first is None else min(first, t)
            last = t if last is None else max(last, t)
            total_bytes += p.wirelen
            cap_bytes += p.caplen
            smin = p.wirelen if smin is None else min(smin, p.wirelen)
            smax = max(smax, p.wirelen)
            if p.caplen < p.wirelen:
                truncated += 1
    except CaptureFormatError as e:
        print("format      : %s" % fmt)
        print("error       : %s" % e)
        return 3
    print("file        : %s" % path)
    print("format      : %s" % fmt)
    print("packets     : %d" % n)
    for lt, c in lts.items():
        supported = "" if lt in (0, 1, 101, 108, 113, 228, 229, 276) else "  (NOT supported by built-in filter engine)"
        print("link type   : %d %s - %d packets%s" % (lt, linktype_name(lt), c, supported))
    if n:
        print("time span   : %.6f s (first %.6f, last %.6f)" % (last - first, first, last))
        print("bytes       : %d on the wire, %d captured" % (total_bytes, cap_bytes))
        print("packet size : min %d, max %d, avg %.1f" % (smin, smax, float(total_bytes) / n))
        if truncated:
            print("truncated   : %d packets captured shorter than on the wire (snaplen)" % truncated)
    return 0


def compare_with_tcpdump(path, expr, ours, only):
    if not find_tcpdump():
        print("-- compare: tcpdump not installed; skipped", file=sys.stderr)
        return 0
    if only is not None:
        print("-- compare: ignoring --packets restriction is not possible with tcpdump; skipped", file=sys.stderr)
        return 0
    try:
        theirs = tcpdump_matching_keys(path, expr)
    except RuntimeError as e:
        print("-- compare: %s" % e, file=sys.stderr)
        return 4
    a = collections.Counter((k, c) for k, c, _ in ours)
    b = collections.Counter(theirs)
    if a == b:
        print("-- compare: tcpdump agrees (%d packets)" % len(theirs), file=sys.stderr)
        return 0
    extra = a - b
    missing = b - a
    print("-- compare: MISMATCH. builtin=%d tcpdump=%d; only-builtin=%d only-tcpdump=%d"
          % (len(ours), len(theirs), sum(extra.values()), sum(missing.values())), file=sys.stderr)
    idx = [i for k, c, i in ours if (k, c) in extra]
    if idx:
        print("   packets matched only by builtin: %s" % ",".join(map(str, idx[:50])), file=sys.stderr)
    return 5


if __name__ == "__main__":
    sys.exit(main())
