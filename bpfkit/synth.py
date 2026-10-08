"""Build synthetic packets / capture files with the standard library only.

Used by the self-test and to (re)generate samples/demo.pcap:
    python3 -m bpfkit.synth samples/demo.pcap
"""

import struct
import sys

from .pcapio import Packet, PcapWriter


def mac(s):
    return bytes(bytearray(int(x, 16) for x in s.split(":")))


def ip4(s):
    return bytes(bytearray(int(x) for x in s.split(".")))


def ip6(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


def csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(src, dst, etype, payload, vlans=()):
    hdr = mac(dst) + mac(src)
    for vid in vlans:
        hdr += struct.pack(">HH", 0x8100, vid)
    return hdr + struct.pack(">H", etype) + payload


def ipv4(src, dst, proto, payload, ttl=64, ident=1, frag=0, mf=False, df=False, opts=b""):
    ihl = (20 + len(opts)) // 4
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag & 0x1FFF)
    h = struct.pack(">BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(opts) + len(payload), ident,
                    flags, ttl, proto, 0, ip4(src), ip4(dst)) + opts
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return h + payload


def ipv6(src, dst, nh, payload, hlim=64):
    return struct.pack(">IHBB16s16s", 0x60000000, len(payload), nh, hlim, ip6(src), ip6(dst)) + payload


def tcp(sport, dport, flags, payload=b"", seq=1000, ack=0, win=64240, opts=b""):
    doff = (20 + len(opts)) // 4
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, win, 0, 0) + opts + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(t, code, payload=b"", ident=1, seq=1):
    h = struct.pack(">BBHHH", t, code, 0, ident, seq) + payload
    return h[:2] + struct.pack(">H", csum(h)) + h[4:]


def arp(op, sha, spa, tha, tpa):
    return struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, mac(sha), ip4(spa), mac(tha), ip4(tpa))


def dns_query(ident, name, qtype=1, response=False, answer_ip=None):
    flags = 0x8180 if response else 0x0100
    q = b"".join(struct.pack("B", len(l)) + l.encode() for l in name.split(".")) + b"\x00"
    q += struct.pack(">HH", qtype, 1)
    an = 0
    body = q
    if response and answer_ip:
        an = 1
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + ip4(answer_ip)
    return struct.pack(">HHHHHH", ident, flags, 1, an, 0, 0) + body


def tls_client_hello(sni):
    name = sni.encode()
    ext_sni = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = ext_sni
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def modbus(tid, unit, func, data):
    pdu = struct.pack("B", func) + data
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


# --------------------------------------------------------------------------

WS, WS_MAC = "10.0.0.10", "00:11:22:33:44:10"
GW_MAC = "00:11:22:33:44:01"
DNS = "10.0.0.53"
HMI, HMI_MAC = "10.0.1.5", "00:11:22:33:55:05"
PLC, PLC_MAC = "10.0.1.20", "00:11:22:33:55:20"
SCAN, SCAN_MAC = "10.0.0.66", "00:11:22:33:44:66"


def demo_frames():
    """Return a list of (relative_time, ethernet_frame) for a small mixed network."""
    f = []
    t = [0.0]

    def add(frame, dt=0.01):
        t[0] += dt
        f.append((t[0], frame))

    # ARP for the gateway
    add(eth(WS_MAC, "ff:ff:ff:ff:ff:ff", 0x0806, arp(1, WS_MAC, WS, "00:00:00:00:00:00", "10.0.0.1")))
    add(eth(GW_MAC, WS_MAC, 0x0806, arp(2, GW_MAC, "10.0.0.1", WS_MAC, WS)))
    # DNS lookups
    for i, (name, ans) in enumerate([("updates.example.com", "93.184.216.34"),
                                     ("intranet.local", "10.0.2.80"),
                                     ("www.google.com", "142.250.1.1")]):
        add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, DNS, 17, udp(40000 + i, 53, dns_query(0x1000 + i, name)))))
        add(eth(GW_MAC, WS_MAC, 0x0800, ipv4(DNS, WS, 17, udp(53, 40000 + i, dns_query(0x1000 + i, name, response=True, answer_ip=ans)))))
    # HTTP
    c, s = 51000, 80
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "93.184.216.34", 6, tcp(c, s, 0x02, seq=100))))
    add(eth(GW_MAC, WS_MAC, 0x0800, ipv4("93.184.216.34", WS, 6, tcp(s, c, 0x12, seq=500, ack=101))))
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "93.184.216.34", 6, tcp(c, s, 0x10, seq=101, ack=501))))
    req = b"GET /firmware/latest HTTP/1.1\r\nHost: updates.example.com\r\nUser-Agent: curl/8\r\n\r\n"
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "93.184.216.34", 6, tcp(c, s, 0x18, req, seq=101, ack=501))))
    add(eth(GW_MAC, WS_MAC, 0x0800, ipv4("93.184.216.34", WS, 6, tcp(s, c, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", seq=501, ack=101 + len(req)))))
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "93.184.216.34", 6, tcp(c, s, 0x11, seq=101 + len(req), ack=540))))
    # TLS
    c = 51001
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "142.250.1.1", 6, tcp(c, 443, 0x02, seq=7000))))
    add(eth(GW_MAC, WS_MAC, 0x0800, ipv4("142.250.1.1", WS, 6, tcp(443, c, 0x12, seq=9000, ack=7001))))
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "142.250.1.1", 6, tcp(c, 443, 0x10, seq=7001, ack=9001))))
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "142.250.1.1", 6, tcp(c, 443, 0x18, tls_client_hello("www.google.com"), seq=7001, ack=9001))))
    # ICMP ping
    for i in range(3):
        add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "10.0.0.1", 1, icmp(8, 0, b"abcdefgh" * 4, seq=i + 1))))
        add(eth(GW_MAC, WS_MAC, 0x0800, ipv4("10.0.0.1", WS, 1, icmp(0, 0, b"abcdefgh" * 4, seq=i + 1))))
    # Modbus/TCP: HMI polls the PLC (reads) and once writes a register
    c = 50200
    add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(c, 502, 0x02, seq=1))))
    add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(PLC, HMI, 6, tcp(502, c, 0x12, seq=1, ack=2))))
    add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(c, 502, 0x10, seq=2, ack=2))))
    seq_c, seq_s = 2, 2
    for i in range(6):
        if i == 4:
            q = modbus(i + 1, 1, 6, struct.pack(">HH", 40, 1234))   # write single register
            r = q
        else:
            q = modbus(i + 1, 1, 3, struct.pack(">HH", 0, 10))      # read holding registers
            r = modbus(i + 1, 1, 3, b"\x14" + b"\x00\x01" * 10)
        add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(c, 502, 0x18, q, seq=seq_c, ack=seq_s))), 0.25)
        seq_c += len(q)
        add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(PLC, HMI, 6, tcp(502, c, 0x18, r, seq=seq_s, ack=seq_c))))
        seq_s += len(r)
    # A SYN port scan against the PLC, answered by RST/ACK (or SYN/ACK on 502)
    for p in (21, 22, 23, 80, 102, 443, 502, 3389):
        add(eth(SCAN_MAC, PLC_MAC, 0x0800, ipv4(SCAN, PLC, 6, tcp(61000, p, 0x02, seq=424242, win=1024), ttl=48)), 0.002)
        flags = 0x12 if p == 502 else 0x14
        add(eth(PLC_MAC, SCAN_MAC, 0x0800, ipv4(PLC, SCAN, 6, tcp(p, 61000, flags, seq=0, ack=424243, win=0))), 0.001)
    # VLAN 20: syslog from a switch
    for i in range(3):
        msg = ("<134>switch1: port %d link up" % (i + 1)).encode()
        add(eth("00:11:22:33:66:05", "00:11:22:33:66:64", 0x0800,
                ipv4("10.20.0.5", "10.20.0.100", 17, udp(514, 514, msg)), vlans=(20,)))
    # IPv6: neighbour solicitation, ping and SSH
    ns = struct.pack(">BBHI", 135, 0, 0, 0) + ip6("fe80::1")
    add(eth(WS_MAC, "33:33:ff:00:00:01", 0x86DD, ipv6("fe80::10", "ff02::1:ff00:1", 58, ns, hlim=255)))
    add(eth(WS_MAC, GW_MAC, 0x86DD, ipv6("2001:db8::10", "2001:db8::1", 58, struct.pack(">BBHHH", 128, 0, 0, 7, 1) + b"ping6")))
    add(eth(GW_MAC, WS_MAC, 0x86DD, ipv6("2001:db8::1", "2001:db8::10", 58, struct.pack(">BBHHH", 129, 0, 0, 7, 1) + b"ping6")))
    add(eth(WS_MAC, GW_MAC, 0x86DD, ipv6("2001:db8::10", "2001:db8::22", 6, tcp(52222, 22, 0x02, seq=1))))
    add(eth(GW_MAC, WS_MAC, 0x86DD, ipv6("2001:db8::22", "2001:db8::10", 6, tcp(22, 52222, 0x12, seq=1, ack=2))))
    add(eth(WS_MAC, GW_MAC, 0x86DD, ipv6("2001:db8::10", "2001:db8::22", 6, tcp(52222, 22, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n", seq=2, ack=2))))
    # NTP
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "10.0.0.1", 17, udp(123, 123, b"\x23" + b"\x00" * 47))))
    add(eth(GW_MAC, WS_MAC, 0x0800, ipv4("10.0.0.1", WS, 17, udp(123, 123, b"\x24" + b"\x00" * 47))))
    # Fragmented UDP datagram (first + second fragment)
    big = udp(40100, 9999, b"X" * 1600)
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "10.0.0.1", 17, big[:1480], ident=777, mf=True)))
    add(eth(WS_MAC, GW_MAC, 0x0800, ipv4(WS, "10.0.0.1", 17, big[1480:], ident=777, frag=1480 // 8)))
    # Broadcast
    add(eth(WS_MAC, "ff:ff:ff:ff:ff:ff", 0x0800, ipv4(WS, "255.255.255.255", 17, udp(68, 67, b"\x01" + b"\x00" * 240))))
    return f


def write_demo(path, start=1767225600):
    write_frames(path, demo_frames(), 1, start)


def write_pcapng(path, frames, linktype=1, start=1767225600):
    """Minimal pcapng writer (SHB + IDB + EPBs), nanosecond resolution."""
    def block(btype, body):
        pad = (-len(body)) % 4
        blen = 12 + len(body) + pad
        return struct.pack("<II", btype, blen) + body + b"\x00" * pad + struct.pack("<I", blen)
    with open(path, "wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # if_tsresol = 10^-9
        f.write(block(1, struct.pack("<HHI", linktype, 0, 262144) + opts))
        for t, frame in frames:
            ts = (start + int(t)) * 10 ** 9 + int(round((t - int(t)) * 1e6)) * 1000
            f.write(block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame))


def _strip_link(frame):
    et = struct.unpack(">H", frame[12:14])[0]
    off = 14
    while et in (0x8100, 0x88A8):
        et = struct.unpack(">H", frame[off + 2:off + 4])[0]
        off += 4
    return et, frame[off:]


def relink(frame, linktype):
    """Re-encapsulate an Ethernet frame for another link type (VLAN tags are
    dropped, as a Linux 'any' capture would). Returns None if impossible."""
    et, payload = _strip_link(frame)
    if linktype == 113:
        return struct.pack(">HHH8sH", 0, 1, 6, frame[6:12] + b"\0\0", et) + payload
    if linktype == 276:
        return struct.pack(">HHIHBB8s", et, 0, 2, 1, 0, 6, frame[6:12] + b"\0\0") + payload
    if et not in (0x0800, 0x86DD):
        return None
    if linktype == 101:
        return payload
    if linktype == 0:
        return struct.pack("<I", 2 if et == 0x0800 else 30) + payload
    if linktype == 108:
        return struct.pack(">I", 2 if et == 0x0800 else 24) + payload
    raise ValueError(linktype)


def write_frames(path, frames, linktype=1, start=1767225600):
    with PcapWriter(path, linktype) as w:
        i = 0
        for t, frame in frames:
            if linktype != 1:
                frame = relink(frame, linktype)
                if frame is None:
                    continue
            i += 1
            sec = start + int(t)
            usec = int(round((t - int(t)) * 1e6))
            w.write(Packet(i, sec, usec, 10 ** 6, len(frame), frame, linktype))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/demo.pcap"
    write_demo(out)
    print("wrote %s (%d packets)" % (out, len(demo_frames())))
