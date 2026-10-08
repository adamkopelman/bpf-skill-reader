"""Self-test: proves the tools work on THIS machine (no network, no tcpdump needed).

    python3 -m bpfkit.selftest          # or: python3 tools/selftest.py

Checks
  1. capture I/O: pcap (us + ns), pcapng, gzip, raw IP / SLL / SLL2 / NULL / LOOP
  2. the filter engine against results recorded from real tcpdump/libpcap
     (bpfkit/expected.py) on Ethernet and Linux-cooked captures
  2b. the engine against tcpdump's answers on real captures (tests/corpus/)
  2c. the unit tests in tests/ (when present)
  3. syntax errors are reported, not silently accepted
  4. bpfgen finds exact filters for known target groups
  5. if tcpdump IS installed: a live cross-check of every expected filter
"""

import gzip
import os
import shutil
import sys
import tempfile

from .bpf import compile_filter, FilterSyntaxError, FilterUnsupported
from .expected import EXPECTED
from .pcapio import read_packets
from .synth import demo_frames, write_frames, write_pcapng
from .util import find_tcpdump, tcpdump_matching_keys

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("  FAIL %s" % msg)


def run_filters(path, cases):
    pkts = list(read_packets(path))
    bad = 0
    for expr, want in cases:
        try:
            flt = compile_filter(expr)
            got = [p.index for p in pkts if flt.match(p)]
        except (FilterSyntaxError, FilterUnsupported) as e:
            got = "error: %s" % e
        if got != want:
            bad += 1
            check(False, "%s: '%s' -> %s, expected %s" % (os.path.basename(path), expr, got, want))
    return len(cases) - bad


def main(argv=None):
    tmp = tempfile.mkdtemp(prefix="bpfkit-selftest-")
    try:
        frames = demo_frames()
        print("[1] capture formats")
        eth = os.path.join(tmp, "demo.pcap")
        write_frames(eth, frames, 1)
        base = [(p.ts_micro(), p.data) for p in read_packets(eth)]
        check(len(base) == len(frames), "pcap round trip count")
        ng = os.path.join(tmp, "demo.pcapng")
        write_pcapng(ng, frames)
        check([(p.ts_micro(), p.data) for p in read_packets(ng)] == base, "pcapng matches pcap")
        gz = os.path.join(tmp, "demo.pcap.gz")
        with open(eth, "rb") as fi, gzip.open(gz, "wb") as fo:
            fo.write(fi.read())
        check([(p.ts_micro(), p.data) for p in read_packets(gz)] == base, "gzip pcap matches pcap")
        for lt in (0, 101, 108, 113, 276):
            path = os.path.join(tmp, "lt%d.pcap" % lt)
            write_frames(path, frames, lt)
            n = sum(1 for _ in read_packets(path))
            check(n > 0, "link type %d readable" % lt)
            flt = compile_filter("tcp port 502")
            m = sum(1 for p in read_packets(path) if flt.match(p))
            check(m == 17, "link type %d: 'tcp port 502' matched %d, expected 17" % (lt, m))
        print("    ok" if not FAILS else "    see failures above")

        print("[2] filter engine vs recorded tcpdump results")
        ok = run_filters(eth, EXPECTED[1])
        print("    Ethernet: %d/%d filters agree" % (ok, len(EXPECTED[1])))
        sll = os.path.join(tmp, "lt113.pcap")
        ok = run_filters(sll, EXPECTED[113])
        print("    Linux SLL: %d/%d filters agree" % (ok, len(EXPECTED[113])))
        ok = run_filters(ng, EXPECTED[1])
        print("    pcapng: %d/%d filters agree" % (ok, len(EXPECTED[1])))

        from . import corpus
        if os.path.exists(corpus.EXPECTED):
            checked, problems = corpus.check_corpus(verbose=False)
            for prob in problems:
                check(False, "corpus: " + prob)
            print("[2b] real captures (tests/corpus): %d checks, %d problems" % (checked, len(problems)))
        else:
            print("[2b] tests/corpus not present - skipped")

        tests_dir = os.path.join(corpus.ROOT, "tests")
        if os.path.isdir(tests_dir):
            import unittest
            suite = unittest.defaultTestLoader.discover(tests_dir, top_level_dir=tests_dir)
            with open(os.devnull, "w") as devnull:
                res = unittest.TextTestRunner(stream=devnull, verbosity=0).run(suite)
            for case, tb in res.failures + res.errors:
                check(False, "unit test %s: %s" % (case, tb.strip().splitlines()[-1]))
            print("[2c] unit tests: %d run, %d failed" % (res.testsRun, len(res.failures) + len(res.errors)))

        print("[3] syntax errors are rejected")
        for bad in ("tcp port", "host 10.0.0.300", "ip[0:3] = 1", "(tcp", "port 99999",
                    "10.0.0.1", "tcp and and udp", "net 10.0.0.1/8"):
            try:
                compile_filter(bad)
                check(False, "accepted invalid filter %r" % bad)
            except (FilterSyntaxError, FilterUnsupported):
                pass
        print("    ok")

        print("[4] bpfgen finds exact filters")
        from . import bpfgen
        cap = bpfgen.Capture(eth, 0)

        class T(object):
            where = contains = contains_hex = flow_of = ignore = None
        cases = [("40,42,44,46,48,50,52,54", "port-scan probes"), ("3,5,7", "DNS queries"),
                 ("56-58", "VLAN syslog"), ("36", "Modbus write"), ("3,5,7,19,21,23", "DNS + ping")]
        for spec, label in cases:
            t = T()
            t.packets = spec
            targets, dontcare, _ = bpfgen.select_targets(cap, t)
            negatives = cap.all & ~targets
            depth = bpfgen.depth_bits(cap)
            feats = [f for f in bpfgen.build_features(cap) if f.bits & targets]
            rules = bpfgen.learn_rules(feats, targets, negatives, depth, 6, 6, 0.0)
            expr = bpfgen.render(rules)
            res = bpfgen.score(cap, expr, targets, 0)
            check(res["fp"] == 0 and res["fn"] == 0, "%s: '%s' fp=%d fn=%d" % (label, expr, res["fp"], res["fn"]))
            print("    %-16s -> %s" % (label, expr))

        td = find_tcpdump()
        if td:
            print("[5] live cross-check against %s" % td)
            agree = 0
            for expr, _want in EXPECTED[1]:
                flt = compile_filter(expr)
                ours = sorted((p.ts_micro(), p.caplen) for p in read_packets(eth) if flt.match(p))
                try:
                    theirs = sorted(tcpdump_matching_keys(eth, expr))
                except RuntimeError as e:
                    check(False, "tcpdump failed on %r: %s" % (expr, e))
                    continue
                if ours == theirs:
                    agree += 1
                else:
                    check(False, "local tcpdump disagrees on %r" % expr)
            print("    %d/%d filters agree with the local tcpdump" % (agree, len(EXPECTED[1])))
        else:
            print("[5] tcpdump not installed - live cross-check skipped (recorded results were used)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nRESULT: %s" % ("PASS" if not FAILS else "FAIL (%d problems)" % len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
