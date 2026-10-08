#!/usr/bin/env python3
"""Compile every filter in the knowledge base's ```bpf blocks.

    python3 tools/check_docs.py [--demo samples/demo.pcap]

Each filter must be accepted by bpfkit. If tcpdump is installed it must also
be accepted by tcpdump, and both must select the same packets in the demo
capture.
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bpfkit.bpf import compile_filter, FilterSyntaxError, FilterUnsupported  # noqa: E402
from bpfkit.pcapio import read_packets  # noqa: E402
from bpfkit.util import find_tcpdump, tcpdump_matching_keys  # noqa: E402


def filters_in(path):
    text = open(path).read()
    for block in re.findall(r"```bpf\n(.*?)```", text, re.S):
        for line in block.splitlines():
            expr = line.split("#", 1)[0].strip()
            if expr:
                yield expr


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    demo = os.path.join(root, "samples", "demo.pcap")
    pkts = list(read_packets(demo))
    td = find_tcpdump()
    bad = total = 0
    for path in sorted(glob.glob(os.path.join(root, "knowledge", "bpf", "*.md"))):
        for expr in filters_in(path):
            total += 1
            try:
                flt = compile_filter(expr)
                ours = sorted((p.ts_micro(), p.caplen) for p in pkts if flt.match(p))
            except (FilterSyntaxError, FilterUnsupported) as e:
                bad += 1
                print("BPFKIT REJECTS %s: %s\n    %s" % (os.path.basename(path), expr, e))
                continue
            if td:
                try:
                    theirs = sorted(tcpdump_matching_keys(demo, expr))
                except RuntimeError as e:
                    bad += 1
                    print("TCPDUMP REJECTS %s: %s\n    %s" % (os.path.basename(path), expr, e))
                    continue
                if ours != theirs:
                    bad += 1
                    print("MISMATCH %s: %s (bpfkit %d, tcpdump %d)" % (os.path.basename(path), expr, len(ours), len(theirs)))
    print("%d filters checked%s, %d problems" % (total, " (with tcpdump)" if td else " (bpfkit only)", bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
