"""Live VLAN behaviour test (Linux, root): how capture filters treat 802.1Q
frames when capturing live versus reading the saved file.

Setup (needs CAP_NET_ADMIN):
    ip link add vtest0 type veth peer name vtest1
    ip link set vtest0 up && ip link set vtest1 up
Run:
    python3 tests/live/live_vlan.py vtest1      # receive side (kernel strips the tag)
    python3 tests/live/live_vlan.py vtest0      # transmit side (tag inline in the frame)
    python3 tests/live/live_vlan.py vtest1 --tool 1.5.3="docker exec centos7 tcpdump"
Cleanup:
    ip link del vtest0

It injects 3 VLAN-20-tagged and 3 untagged UDP frames on vtest0 with a packet
socket, captures them live with each tcpdump build (with and without filters),
and compares with the same filter applied offline and by bpfkit. Results are
recorded in knowledge/bpf/08-libpcap-versions.md.
"""
import argparse
import os
import shlex
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from bpfkit import synth  # noqa: E402
from bpfkit.bpf import compile_filter  # noqa: E402
from bpfkit.pcapio import read_packets  # noqa: E402

OUT = None  # set in main(); must be visible to docker-based tools at the same path

TAGGED = synth.eth("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800,
                   synth.ipv4("10.20.0.5", "10.20.0.100", 17, synth.udp(514, 514, b"tagged")), vlans=(20,))
UNTAGGED = synth.eth("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800,
                     synth.ipv4("10.0.0.5", "10.0.0.100", 17, synth.udp(515, 515, b"plain")))
FILTERS = ["", "ip", "udp", "vlan", "vlan 20", "vlan and ip", "vlan and udp port 514",
           "ip or (vlan and ip)", "(vlan and ip) or ip", "not vlan", "udp port 514", "ether[12:2] = 0x8100"]


def send(n=3):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("vtest0", 0))
    for _ in range(n):
        s.send(TAGGED)
        s.send(UNTAGGED)
        time.sleep(0.05)


def live_capture(tool, flt, path, iface="vtest1"):
    cmd = tool[:-1] + ["timeout", "-s", "INT", "3"] + [tool[-1], "-i", iface, "-nn", "-U", "-w", path]
    if flt:
        cmd.append(flt)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)
    send()
    out, err = p.communicate()
    return err.decode(errors="replace")


def count(path):
    try:
        pk = list(read_packets(path))
    except Exception:
        return None, []
    return len(pk), pk


def offline(tool, src, flt):
    r = subprocess.run(tool + ["-r", src, "-nn", flt] if flt else tool + ["-r", src, "-nn"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = [ln for ln in r.stdout.decode().splitlines() if ln.strip()]
    return len(lines) if r.returncode == 0 else "ERR"


def main():
    global OUT
    ap = argparse.ArgumentParser(description="live VLAN capture-filter test")
    ap.add_argument("iface", nargs="?", default="vtest1")
    ap.add_argument("--tool", action="append", default=[],
                    help='LABEL="tcpdump command", e.g. 1.5.3="docker exec centos7 tcpdump" (repeatable)')
    ap.add_argument("--out", default="/tmp/bpfkit-live-vlan")
    args = ap.parse_args()
    OUT = args.out
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    tools = [("local", ["tcpdump"])] + [(t.split("=", 1)[0], shlex.split(t.split("=", 1)[1])) for t in args.tool]
    iface = args.iface
    rows = []
    for ver, tool in tools:
        allpath = os.path.join(OUT, "all-%s-%s.pcap" % (ver, iface))
        live_capture(tool, "", allpath, iface)
        n_all, pk_all = count(allpath)
        tagged_inline = sum(1 for p in pk_all if p.data[12:14] == b"\x81\x00")
        print("libpcap %s on %s: unfiltered live capture has %s packets, %d with an inline 802.1Q tag"
              % (ver, iface, n_all, tagged_inline))
        for f in FILTERS:
            path = os.path.join(OUT, "f-%s-%s-%d.pcap" % (ver, iface, FILTERS.index(f)))
            live_capture(tool, f, path, iface)
            n_live, _ = count(path)
            n_off = offline(tool, allpath, f)
            ours = sum(1 for p in pk_all if compile_filter(f).match(p)) if f else n_all
            rows.append((ver, f or "(none)", n_live, n_off, ours))
    print("\n%-8s %-26s %6s %8s %7s" % ("libpcap", "filter", "live", "offline", "bpfkit"))
    for r in rows:
        print("%-8s %-26s %6s %8s %7s" % r)


if __name__ == "__main__":
    main()
