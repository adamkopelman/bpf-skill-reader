"""Small shared helpers."""

import os
import shutil
import subprocess
import tempfile


def parse_index_spec(spec):
    """'1,4,10-20' -> set of ints (1-based packet numbers)."""
    out = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            out.update(range(a, b + 1))
        else:
            out.add(int(part))
    return out


def popcount(x):
    try:
        return x.bit_count()
    except AttributeError:  # Python < 3.10
        return bin(x).count("1")


def bitset_from_indices(indices, n):
    """Build an int bitset (bit i = packet position i) efficiently."""
    buf = bytearray((n + 8) // 8)
    for i in indices:
        buf[i >> 3] |= 1 << (i & 7)
    return int.from_bytes(bytes(buf), "little")


def bits_to_positions(bits):
    s = bin(bits)[2:][::-1]
    return [i for i, ch in enumerate(s) if ch == "1"]


def find_tcpdump():
    return shutil.which("tcpdump")


def tcpdump_compile(expr, linktype_name="EN10MB"):
    """Return `tcpdump -d` output for expr, or None if tcpdump is unavailable."""
    td = find_tcpdump()
    if not td:
        return None
    try:
        r = subprocess.run([td, "-d", "-y", linktype_name, expr],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return "tcpdump failed: %s" % e
    if r.returncode != 0:
        return "tcpdump rejected the filter: %s" % r.stderr.strip()
    return r.stdout


def tcpdump_matching_keys(path, expr):
    """Run `tcpdump -r path -w tmp expr`; return list of (ts_sec, ts_usec, caplen)
    for packets tcpdump kept, or raise RuntimeError."""
    from .pcapio import read_packets
    td = find_tcpdump()
    if not td:
        raise RuntimeError("tcpdump not found in PATH")
    fd, tmp = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        r = subprocess.run([td, "-r", path, "-w", tmp, expr],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError("tcpdump: %s" % r.stderr.strip())
        return [(p.ts_micro(), p.caplen) for p in read_packets(tmp)]
    finally:
        os.unlink(tmp)


LINKTYPE_TO_DLT_NAME = {0: "NULL", 1: "EN10MB", 101: "RAW", 108: "LOOP",
                        113: "LINUX_SLL", 228: "IPV4", 229: "IPV6",
                        276: "LINUX_SLL2"}
