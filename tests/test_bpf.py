"""Unit tests for the filter language (tokenizer, parser, evaluation).

Run:  python3 -m unittest discover -s tests      (stdlib only, Python 3.5+)
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bpfkit.bpf import (tokenize, compile_filter, FilterSyntaxError,  # noqa: E402
                        FilterUnsupported)
from bpfkit.pcapio import Packet  # noqa: E402
from bpfkit import synth  # noqa: E402


def toks(text):
    return [(t.kind, t.val) for t in tokenize(text)][:-1]


def pkt(frame, linktype=1, wirelen=None):
    return Packet(1, 0, 0, 10 ** 6, wirelen or len(frame), frame, linktype)


def tcp_frame(flags=0x02, sport=40000, dport=80, payload=b"", src="10.0.0.1", dst="10.0.0.2",
              vlans=(), opts=b""):
    return synth.eth("00:00:00:00:00:01", "00:00:00:00:00:02", 0x0800,
                     synth.ipv4(src, dst, 6, synth.tcp(sport, dport, flags, payload, opts=opts)),
                     vlans=vlans)


class TokenizerTests(unittest.TestCase):
    def test_bracket_index_is_not_ipv6_or_mac(self):
        self.assertEqual(toks("tcp[13:1]"), [("id", "tcp"), ("op", "["), ("num", "13"),
                                              ("op", ":"), ("num", "1"), ("op", "]")])

    def test_addresses(self):
        self.assertEqual(toks("aa:bb:cc:dd:ee:ff"), [("mac", "aa:bb:cc:dd:ee:ff")])
        self.assertEqual(toks("aabb.ccdd.eeff"), [("mac", "aabb.ccdd.eeff")])
        self.assertEqual(toks("fe80::1"), [("ip6", "fe80::1")])
        self.assertEqual(toks("1:2:3:4:5:6:7:8"), [("ip6", "1:2:3:4:5:6:7:8")])
        self.assertEqual(toks("2001:db8::/32"), [("ip6", "2001:db8::/32")])
        self.assertEqual(toks("10.0.0.0/8"), [("ip4", "10.0.0.0/8")])

    def test_numbers(self):
        self.assertEqual(toks("0x1F 017 08"), [("num", "0x1F"), ("num", "017"), ("num", "08")])

    def test_portrange_token_only_after_portrange(self):
        self.assertEqual(toks("portrange 1-1024"), [("id", "portrange"), ("range", "1-1024")])

    def test_minus_needs_spaces_like_libpcap(self):
        self.assertEqual(toks("len-14"), [("id", "len-14")])
        self.assertEqual(toks("len - 14"), [("id", "len"), ("op", "-"), ("num", "14")])

    def test_named_constants_with_dashes(self):
        self.assertEqual(toks("tcp-syn|tcp-ack"), [("id", "tcp-syn"), ("op", "|"), ("id", "tcp-ack")])

    def test_escaped_protocol_name(self):
        self.assertEqual(toks("ip proto \\tcp")[-1], ("id", "\\tcp"))

    def test_bad_character(self):
        with self.assertRaises(FilterSyntaxError):
            tokenize("tcp port 80 $ 1")


class ParserStructureTests(unittest.TestCase):
    def parsed(self, text):
        return str(compile_filter(text))

    def test_and_or_equal_precedence_left_to_right(self):
        self.assertEqual(self.parsed("tcp or udp and icmp"), "((tcp or udp) and icmp)")
        self.assertEqual(self.parsed("not tcp and udp or icmp"), "(((not tcp) and udp) or icmp)")

    def test_qualifier_carry_over(self):
        self.assertEqual(self.parsed("tcp dst port 21 or 22"), "(tcp dst port 21 or tcp dst port 22)")
        self.assertEqual(self.parsed("host 1.2.3.4 or 5.6.7.8 and port 80"),
                         "((host 1.2.3.4 or host 5.6.7.8) and port 80)")

    def test_protocol_abbreviation_resets_carry_over(self):
        with self.assertRaises(FilterSyntaxError):
            compile_filter("port 80 or tcp or 443")

    def test_arithmetic_precedence_is_c_like(self):
        self.assertEqual(self.parsed("ip[0] & 0xf + 1 << 2 | 3 = 7"),
                         "((ip[0:1] & ((15 + 1) << 2)) | 3) = 7")

    def test_named_constants(self):
        self.assertEqual(self.parsed("tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn"),
                         "(tcp[13:1] & (2 | 16)) = 2")
        self.assertEqual(self.parsed("icmp[icmptype] = icmp-echo"), "icmp[0:1] = 8")

    def test_relation_and_boolean_parentheses(self):
        self.assertEqual(self.parsed("(tcp[13] & 2 != 0)"), "(tcp[13:1] & 2) != 0")
        self.assertEqual(self.parsed("((tcp[12] & 0xf0) >> 2) > 20"), "((tcp[12:1] & 240) >> 2) > 20")
        self.assertEqual(self.parsed("(tcp port 80)"), "tcp port 80")

    def test_dir_combinations(self):
        self.assertEqual(self.parsed("src or dst port 53"), "src or dst port 53")
        self.assertEqual(self.parsed("src and dst net 10.0.0.0/8"), "src and dst net 10.0.0.0/8")

    def test_octal_and_hex(self):
        self.assertEqual(self.parsed("ip[9] = 021"), "ip[9:1] = 17")
        self.assertEqual(self.parsed("ip[9] = 0x11"), "ip[9:1] = 17")

    def test_empty_filter_matches_everything(self):
        self.assertTrue(compile_filter("").match(pkt(tcp_frame())))
        self.assertTrue(compile_filter(None).match(pkt(tcp_frame())))


class SyntaxErrorTests(unittest.TestCase):
    BAD = [
        "tcp port", "port", "host", "(tcp", "tcp)", "tcp and", "and tcp", "tcp and and udp",
        "host 10.0.0.300", "host 10.0.0", "net 10.0.0.1/8", "net 10.0.0.0/33",
        "port 99999", "portrange 10-", "ip[0:3] = 1", "ip[0] =", "= 1", "ip[0] 1",
        "10.0.0.1", "len-14 > 1", "ether host 10.0.0.1", "tcp host 10.0.0.1",
        "ip6 host 10.0.0.1", "ip host fe80::1", "ip proto \\nosuch", "ether proto \\nosuch",
        "port nosuchservice", "tcp[1", "ether", "ip6 host fe80::/10",
    ]
    UNSUPPORTED = ["mpls", "pppoes", "gateway 10.0.0.1", "ip protochain 6", "wlan host 00:11:22:33:44:55",
                   "decnet host 10.0.0.1", "inbound"]

    def test_rejected(self):
        for f in self.BAD:
            with self.assertRaises((FilterSyntaxError, FilterUnsupported), msg=f):
                compile_filter(f)

    def test_unsupported_is_reported_as_such(self):
        for f in self.UNSUPPORTED:
            with self.assertRaises((FilterUnsupported, FilterSyntaxError), msg=f):
                compile_filter(f)
        with self.assertRaises(FilterUnsupported):
            compile_filter("mpls")

    def test_hostnames_need_opt_in(self):
        with self.assertRaises(FilterSyntaxError) as cm:
            compile_filter("host plc-01")
        self.assertIn("--allow-dns", str(cm.exception))
        # opting in resolves (localhost always resolves without a network)
        compile_filter("host localhost", allow_dns=True)


class EvaluationTests(unittest.TestCase):
    def m(self, text, frame, **kw):
        return compile_filter(text).match(pkt(frame, **kw))

    def test_flags(self):
        syn, synack, rst = tcp_frame(0x02), tcp_frame(0x12), tcp_frame(0x14)
        f = "tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn"
        self.assertTrue(self.m(f, syn))
        self.assertFalse(self.m(f, synack))
        self.assertTrue(self.m("tcp[tcpflags] & tcp-rst != 0", rst))

    def test_payload_offset_with_tcp_options(self):
        # 12 bytes of TCP options: a hard-coded tcp[20] is wrong, the computed offset is right
        frame = tcp_frame(0x18, payload=b"GET / HTTP/1.1\r\n", opts=b"\x01" * 12)
        self.assertTrue(self.m("tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420", frame))
        self.assertFalse(self.m("tcp[20:4] = 0x47455420", frame))

    def test_out_of_bounds_load_rejects_whole_packet(self):
        frame = tcp_frame(0x02)
        self.assertTrue(self.m("ip", frame))
        self.assertFalse(self.m("tcp[100] = 1 or ip", frame))   # libpcap unoptimised semantics
        self.assertTrue(self.m("ip or tcp[100] = 1", frame))    # short-circuit before the load

    def test_protocol_mismatch_makes_relation_false_not_reject(self):
        arp = synth.eth("00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 0x0806,
                        synth.arp(1, "00:00:00:00:00:01", "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"))
        self.assertFalse(self.m("ip[9] = 6", arp))
        self.assertTrue(self.m("not ip[9] = 6", arp))
        self.assertTrue(self.m("host 10.0.0.2", arp))      # host includes ARP
        self.assertFalse(self.m("ip host 10.0.0.2", arp))

    def test_vlan_shifts_later_offsets(self):
        tagged = tcp_frame(vlans=(20,))
        plain = tcp_frame()
        self.assertFalse(self.m("ip", tagged))
        self.assertTrue(self.m("vlan 20 and ip", tagged))
        self.assertTrue(self.m("ip or (vlan and ip)", tagged))
        self.assertTrue(self.m("ip or (vlan and ip)", plain))
        self.assertFalse(self.m("(vlan and ip) or ip", plain))  # second 'ip' is shifted
        self.assertTrue(self.m("vlan and vlan", tcp_frame(vlans=(100, 200))))
        self.assertTrue(self.m("vlan 100 and vlan 200 and tcp port 80", tcp_frame(vlans=(100, 200))))

    def test_ipv4_fragments_have_no_ports(self):
        first = synth.eth("00:00:00:00:00:01", "00:00:00:00:00:02", 0x0800,
                          synth.ipv4("10.0.0.1", "10.0.0.2", 17, synth.udp(1, 53, b"x" * 16), mf=True))
        later = synth.eth("00:00:00:00:00:01", "00:00:00:00:00:02", 0x0800,
                          synth.ipv4("10.0.0.1", "10.0.0.2", 17, b"y" * 16, frag=2))
        self.assertTrue(self.m("udp port 53", first))
        self.assertFalse(self.m("udp port 53", later))
        self.assertTrue(self.m("udp and host 10.0.0.2", later))

    def test_ipv6(self):
        f6 = synth.eth("00:00:00:00:00:01", "00:00:00:00:00:02", 0x86DD,
                       synth.ipv6("2001:db8::1", "2001:db8::2", 6, synth.tcp(1234, 443, 0x02)))
        self.assertTrue(self.m("ip6 and tcp port 443", f6))
        self.assertTrue(self.m("net 2001:db8::/32", f6))
        self.assertFalse(self.m("tcp[13] & 2 != 0", f6))           # tcp[] is IPv4-only
        self.assertTrue(self.m("ip6[6] = 6 and ip6[53] & 2 != 0", f6))
        # a hop-by-hop header hides the ports from libpcap
        hbh = b"\x06\x00" + b"\x00" * 6
        f6h = synth.eth("00:00:00:00:00:01", "00:00:00:00:00:02", 0x86DD,
                        synth.ipv6("2001:db8::1", "2001:db8::2", 0, hbh + synth.tcp(1234, 443, 0x02)))
        self.assertFalse(self.m("tcp port 443", f6h))
        self.assertFalse(self.m("tcp", f6h))

    def test_len_less_greater_are_inclusive(self):
        frame = tcp_frame()
        n = len(frame)
        self.assertTrue(self.m("less %d" % n, frame))
        self.assertTrue(self.m("greater %d" % n, frame))
        self.assertFalse(self.m("len > %d" % n, frame))

    def test_wire_length_not_captured_length(self):
        frame = tcp_frame()
        self.assertTrue(compile_filter("len = 1500").match(pkt(frame, wirelen=1500)))

    def test_division_by_zero(self):
        # a divisor libpcap can fold to 0 is a compile error, like tcpdump's
        for f in ("ip[0] / 0 = 1", "ip[0] / (ip[1] & 0) = 1", "ip[0] % (ip[0] - ip[0]) = 1"):
            with self.assertRaises(FilterSyntaxError):
                compile_filter(f)
        # a divisor that is 0 only at run time rejects the whole packet (BPF returns 0)
        self.assertFalse(self.m("ip[0] / (ip[1] & 1) = 1 or ip", tcp_frame()))

    def test_link_types(self):
        frame = tcp_frame()
        raw = synth.relink(frame, 101)
        sll = synth.relink(frame, 113)
        for lt, data in ((101, raw), (113, sll), (276, synth.relink(frame, 276)),
                         (0, synth.relink(frame, 0)), (108, synth.relink(frame, 108))):
            self.assertTrue(compile_filter("tcp port 80 and host 10.0.0.2").match(pkt(data, lt)), lt)
        with self.assertRaises(FilterUnsupported):
            compile_filter("ether host 00:00:00:00:00:01").match(pkt(raw, 101))
        with self.assertRaises(FilterUnsupported):
            compile_filter("vlan").match(pkt(sll, 113))

    def test_null_loopback_either_byte_order(self):
        payload = synth.ipv4("10.0.0.1", "10.0.0.2", 17, synth.udp(1, 2, b""))
        for af in (struct.pack("<I", 2), struct.pack(">I", 2)):
            self.assertTrue(compile_filter("udp").match(pkt(af + payload, 0)))


if __name__ == "__main__":
    unittest.main()
