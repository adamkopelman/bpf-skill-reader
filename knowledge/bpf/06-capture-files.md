# Capture file formats and link types

## `.cap` is not one format

The extension `.cap` has been used by several unrelated products. Identify the
file by its first bytes; `tools/capread.py FILE --info` does this for you.

| First bytes (hex / text) | Format | capread |
|---|---|---|
| `d4 c3 b2 a1` / `a1 b2 c3 d4` | libpcap, µs timestamps (LE / BE). tcpdump, most `.cap`/`.pcap` | yes |
| `4d 3c b2 a1` / `a1 b2 3c 4d` | libpcap, ns timestamps | yes |
| `34 cd b2 a1` | "modified" pcap (Kuznetsov, old Red Hat tcpdump) | yes |
| `0a 0d 0d 0a` | pcapng (Wireshark/dumpcap default) | yes |
| `73 6e 6f 6f 70 00 00 00` "snoop" | Solaris snoop | yes (Ethernet) |
| `1f 8b` | gzip, any of the above inside (`.pcap.gz`) | yes |
| `47 4d 42 55` "GMBU" | Microsoft Network Monitor 2.x `.cap` | convert |
| `52 54 53 53` "RTSS" | Microsoft Network Monitor 1.x `.cap` | convert |
| "TRSNIFF data" | NAI / Network General Sniffer `.cap`/`.enc` | convert |
| `58 43 50 00` "XCP" | NetXray / Windows Sniffer `.cap` | convert |

Convert on a machine with Wireshark tools, then carry the result over:

```sh
editcap -F pcap  input.cap output.pcap      # any Wireshark-readable format -> pcap
editcap -F pcapng input.cap output.pcapng
capinfos input.cap                          # what is it? (Wireshark's file info tool)
mergecap -w all.pcap a.pcap b.pcap          # merge by timestamp
editcap -c 100000 big.pcap part.pcap        # split by packet count
editcap -A '2026-01-01 08:00:00' -B '2026-01-01 09:00:00' in.pcap out.pcap   # time slice
```

## classic pcap layout

```
global header (24 bytes): magic(4) ver_major(2)=2 ver_minor(2)=4 thiszone(4) sigfigs(4) snaplen(4) linktype(4)
per packet (16 bytes):    ts_sec(4) ts_usec_or_nsec(4) incl_len(4) orig_len(4)  then incl_len bytes
```

- `incl_len < orig_len` means the packet was truncated by the snapshot length
  (`tcpdump -s`). Payload filters can fail on truncated packets (gotcha 6).
- Everything is in the byte order given by the magic number.

## pcapng in one paragraph

A pcapng file is a sequence of blocks: `type(4) length(4) body ... length(4)`.

- A Section Header Block (`0x0A0D0D0A`, with byte-order magic `0x1A2B3C4D`)
  starts each section.
- Interface Description Blocks (type 1) declare the link type, snaplen and
  timestamp resolution (`if_tsresol`) of each interface.
- Packets are Enhanced Packet Blocks (type 6). Each one names its interface,
  so one file can mix link types.
- Simple Packet (3), Name Resolution (4), Interface Statistics (5) and other
  blocks may appear.

capread reads EPB, SPB and the obsolete type 2. It ignores the others.

## Link types the filter engine understands

| Link type | Name | Network header at | Notes |
|---|---|---|---|
| 1 | EN10MB (Ethernet) | 14 (+4 per VLAN tag) | full support incl. `ether`, `vlan` |
| 101 / 228 / 229 | RAW / IPV4 / IPV6 | 0 | version nibble decides IPv4/IPv6 |
| 113 | LINUX_SLL (`tcpdump -i any`, older) | 16 | no Ethernet header, no VLAN tags |
| 276 | LINUX_SLL2 (`-i any`, libpcap >= 1.10) | 20 | " |
| 0 | NULL (BSD loopback) | 4 | AF value in host byte order |
| 108 | LOOP (OpenBSD loopback) | 4 | AF value in network byte order |
| 105 / 127 | IEEE802_11 / RADIOTAP (Wi-Fi) | - | **not supported**: list only; filter with tcpdump |

`ether host`, `vlan`, `broadcast` and `multicast` need Ethernet. On other link
types capread reports an error instead of guessing.

## Timestamps

- pcap stores UTC seconds plus µs or ns.
- capread prints `HH:MM:SS.ffffff` UTC, or full dates with `--abs-time`.
- Air-gapped hosts often have drifting clocks. Compare against the capture's
  own first and last timestamps (`--info`), not against wall-clock time.
