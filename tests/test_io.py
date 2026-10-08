"""Unit tests for capture I/O and the decoder's robustness.

Run:  python3 -m unittest discover -s tests
"""

import gzip
import os
import random
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bpfkit import decode, synth  # noqa: E402
from bpfkit.bpf import compile_filter  # noqa: E402
from bpfkit.pcapio import (read_packets, detect_format, CaptureFormatError,  # noqa: E402
                           PcapWriter, Packet)


class CaptureIOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.frames = synth.demo_frames()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def test_pcap_roundtrip_and_formats(self):
        p = self.path("a.pcap")
        synth.write_frames(p, self.frames)
        self.assertEqual(detect_format(p), "pcap")
        pk = list(read_packets(p))
        self.assertEqual([x.data for x in pk], [f for _, f in self.frames])
        self.assertEqual([x.index for x in pk], list(range(1, len(self.frames) + 1)))

        ng = self.path("a.pcapng")
        synth.write_pcapng(ng, self.frames)
        self.assertEqual(detect_format(ng), "pcapng")
        self.assertEqual([(x.ts_micro(), x.data) for x in read_packets(ng)],
                         [(x.ts_micro(), x.data) for x in pk])

        gz = self.path("a.pcap.gz")
        with open(p, "rb") as fi, gzip.open(gz, "wb") as fo:
            fo.write(fi.read())
        self.assertEqual(detect_format(gz), "gzip+pcap")
        self.assertEqual(len(list(read_packets(gz))), len(pk))

    def test_big_endian_and_nanosecond_pcap(self):
        frame = self.frames[0][1]
        for magic, endian, div in ((0xA1B2C3D4, ">", 10 ** 6), (0xA1B23C4D, "<", 10 ** 9)):
            p = self.path("x.pcap")
            with open(p, "wb") as f:
                f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
                f.write(struct.pack(endian + "IIII", 100, div // 2, len(frame), len(frame)) + frame)
            (pk,) = list(read_packets(p))
            self.assertEqual(pk.data, frame)
            self.assertEqual(pk.ts_micro(), (100, 500000))

    def test_truncated_file_stops_cleanly(self):
        p = self.path("t.pcap")
        synth.write_frames(p, self.frames[:5])
        with open(p, "rb") as f:
            data = f.read()
        with open(p, "wb") as f:
            f.write(data[:-10])  # cut the last record
        self.assertEqual(len(list(read_packets(p))), 4)

    def test_snaplen_truncated_packets(self):
        p = self.path("s.pcap")
        frame = self.frames[11][1]  # HTTP GET
        with PcapWriter(p, 1) as w:
            w.write(Packet(1, 0, 0, 10 ** 6, len(frame), frame[:60], 1))
        (pk,) = list(read_packets(p))
        self.assertEqual((pk.caplen, pk.wirelen), (60, len(frame)))
        self.assertTrue(compile_filter("tcp port 80").match(pk))
        # payload beyond the snaplen: the load is out of range and rejects the packet
        self.assertFalse(compile_filter("tcp[((tcp[12:1] & 0xf0) >> 2) + 10] = 0x41 or tcp").match(pk))
        decode.summary(decode.decode(pk))  # must not raise

    def test_empty_and_unknown_files(self):
        p = self.path("empty.cap")
        open(p, "wb").close()
        with self.assertRaises(CaptureFormatError):
            list(read_packets(p))
        for magic, name in ((b"GMBU\x00\x02", "Network Monitor"), (b"TRSNIFF data    \x1a", "Sniffer"),
                            (b"hello world!", "unrecognised")):
            with open(p, "wb") as f:
                f.write(magic + b"\x00" * 32)
            with self.assertRaises(CaptureFormatError) as cm:
                list(read_packets(p))
            self.assertIn(name, str(cm.exception))

    def test_writer_rejects_mixed_linktypes(self):
        with PcapWriter(self.path("w.pcap"), 1) as w:
            with self.assertRaises(CaptureFormatError):
                w.write(Packet(1, 0, 0, 10 ** 6, 20, b"\x45" + b"\x00" * 19, 101))


class DecoderFuzzTests(unittest.TestCase):
    def test_decoder_never_raises_on_garbage(self):
        rnd = random.Random(1234)
        frames = [f for _, f in synth.demo_frames()]
        eth_flt = compile_filter("tcp port 80 or udp[8] = 1 or ether broadcast or vlan and ip or ip6 and icmp6")
        l3_flt = compile_filter("tcp port 80 or udp[8] = 1 or ip6 and icmp6 or ip[6:2] & 0x1fff != 0")
        for i in range(3000):
            base = bytearray(rnd.choice(frames))
            cut = rnd.randrange(0, len(base) + 1)
            base = base[:cut]
            for _ in range(rnd.randrange(0, 6)):
                if base:
                    base[rnd.randrange(len(base))] = rnd.randrange(256)
            lt = rnd.choice((1, 1, 1, 101, 113, 276, 0))
            p = Packet(i + 1, 0, 0, 10 ** 6, len(base), bytes(base), lt)
            d = decode.decode(p)
            decode.summary(d)
            decode.verbose_lines(d)
            (eth_flt if lt == 1 else l3_flt).match(p)


class BpfgenRobustnessTests(unittest.TestCase):
    def test_profile_and_suggest_on_mangled_capture(self):
        import contextlib
        import io
        from bpfkit import bpfgen
        rnd = random.Random(99)
        frames = []
        for t, f in synth.demo_frames():
            f = bytearray(f)
            if rnd.random() < 0.5:
                f = f[:rnd.randrange(10, len(f) + 1)]
            frames.append((t, bytes(f)))
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "m.pcap")
            synth.write_frames(p, frames)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(bpfgen.main(["profile", p]), 0)
                self.assertEqual(bpfgen.main(["suggest", p, "--packets", "1-10", "--no-tcpdump"]), 0)
            self.assertIn("suggested filters", out.getvalue())
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
