# BPF gotchas (verified against tcpdump 4.99.4 / libpcap 1.10.4)

Packet counts refer to `samples/demo.pcap`. Reproduce any of them with
`python3 tools/capread.py samples/demo.pcap 'FILTER' --stats` or
`tcpdump -r samples/demo.pcap 'FILTER' | wc -l`.

## 1. `and` / `or` have equal precedence (left to right)

```
host 10.0.0.53 and port 53 or icmp        -> 12 packets  = (host .53 and port 53) or icmp
host 10.0.0.53 and (port 53 or icmp)      ->  6 packets
not host 10.0.0.10 or 10.0.0.53           -> 46 packets  = (not host .10) or host .53
not (host 10.0.0.10 or host 10.0.0.53)    -> 40 packets
```

Parenthesise every mixed `and`/`or` expression. `bpfgen` always does.

## 2. Bare values inherit qualifiers; a lone value is an error

`tcp dst port 21 or 22` means `tcp dst port 21 or tcp dst port 22`. But
`10.0.0.1` on its own is a syntax error in libpcap. Write `host 10.0.0.1`.

## 3. `vlan` shifts every LATER offset by 4 bytes, including across `or`

libpcap compiles `vlan` by adding 4 to the link-layer offset for everything
that follows it in the expression text. It is not scoped by parentheses or
`or`.

```
ip or (vlan and ip)       -> 61 packets  (untagged IPv4 + tagged IPv4)   correct
(vlan and ip) or ip       ->  5 packets  (second "ip" is ALSO shifted)   wrong
ip or vlan                -> 61 packets
vlan or ip                ->  5 packets  ("ip" here looks 4 bytes too deep)
```

Rules:
- Put the untagged alternatives first and the `vlan ...` part last.
- Use exactly one `vlan` per tag level. `vlan and vlan` means QinQ.
- To test a VLAN id without shifting anything, use the absolute form
  `ether[12:2] = 0x8100 and ether[14:2] & 0x0fff = 20`.
- `ether[...]` and `ether host` are never shifted.

**Live capture on Linux is different.** The kernel usually strips the VLAN tag
into metadata before the filter runs, and recent libpcap compiles `vlan` into
a check of that metadata. On a live interface, a plain `ip` filter may
therefore match tagged traffic that the same filter misses when you read the
saved file. A `-i any` (Linux cooked) capture has no tags at all. When VLANs
matter, test the filter both live and offline. `ip or (vlan and ip)` works in
both cases.

## 4. `tcp[...]`, `udp[...]`, `icmp[...]` are IPv4-only

`tcp[13] & 2 != 0` never matches IPv6. The relation is false for every packet
that is not IPv4 TCP. It also never matches non-first fragments. For IPv6,
index from the IPv6 header and guard the next header:

```
ip6[6] = 6 and ip6[53] & 0x02 != 0                 # IPv6 TCP SYN (40 + 13)
```

`port`, `host`, `net`, `tcp` and `udp` do work for IPv6.

## 5. IPv6 extension headers are not walked

BPF has no loops. `port 80` on IPv6 assumes TCP/UDP starts at byte 40. If a
hop-by-hop, routing or destination-options header comes first, `port`
filters miss the packet. `tcp`, `udp` and `ip6 proto N` look one Fragment
header deep, but no further.

## 6. Out-of-bounds loads reject the whole packet

If any load reaches past the captured bytes, the BPF program returns 0. This
happens with a payload byte of a packet that has no payload, or a packet cut
short by snaplen. The packet is dropped even if another `or` branch would
have accepted it:

```
tcp[100] = 1 or ip        -> 17 packets with tcpdump -O (unoptimised) and with bpfkit
                          -> 58 packets with default tcpdump (the optimiser happens to test "ip" first)
```

Don't rely on either behaviour:
- Put payload-indexing terms last.
- Guard them with the protocol and port.
- Never assume a short packet will "just not match".
- Capture with `-s 0` (full packets) when you filter on payload.

## 7. Hard-coded header lengths break

`tcp[20:4] = 0x47455420` (HTTP GET) only works when the TCP header has no
options. SYNs and most Linux and Windows traffic carry options. Use
`tcp[((tcp[12:1] & 0xf0) >> 2):4]`. The `tcp[]`/`udp[]` bases already account
for IPv4 options, so never add 20 for the IP header.

## 8. Unary minus is broken in libpcap

`-ip[9] = 0xfffffffa` compiles in libpcap 1.10.4 to a program that **accepts
every packet**, and `tcpdump -d` prints nothing. Write `0 - ip[9]` instead.
bpfkit evaluates both correctly (41 packets), so its result will disagree
with tcpdump here.

## 9. `len`, `less`, `greater`

- `len` is the original on-the-wire length, including the link-layer header
  but excluding the FCS. It is not the IP total length.
- `less N` means `len <= N` and `greater N` means `len >= N`. Both are
  inclusive.

## 10. `host` also matches ARP

`host 10.0.0.1` = `ip host 10.0.0.1 or arp host 10.0.0.1 or rarp host 10.0.0.1`.
Use `ip host` when you only want IP packets.

## 11. Fragments have no ports

Non-first IPv4 fragments carry no TCP/UDP header. `port 53`, `tcp[...]` and
`udp[...]` never match them, while `host` does. To keep whole fragmented
datagrams, add `or (host X and ip[6:2] & 0x1fff != 0)`.

## 12. No DNS, no services file? Use numbers

On an air-gapped host, `host server1` fails (or hangs while the resolver times
out), and `port http` needs `/etc/services`. Use IP addresses and port
numbers. Run tcpdump with `-nn` so it doesn't try to resolve names in its
output either.

## 13. `ip broadcast` depends on the netmask

Live tcpdump uses the interface netmask, so a directed broadcast like
10.0.0.255 also counts. When you read a file, tcpdump uses netmask 0, so only
255.255.255.255 and 0.0.0.0 count. bpfkit does the same. Programs that hand
libpcap an *unknown* netmask get the error "netmask not known". For a specific
directed broadcast, write it out: `ip[16:4] = 0x0a0000ff` (10.0.0.255).

## 14. `ether proto` values <= 1500

Values up to 1500 are 802.3 lengths, not EtherTypes. libpcap gives
`ether proto N` LLC semantics for them. To match LLC/STP traffic, use MAC or
LLC bytes (`ether[14:2] = 0x4242` for STP) or `ether dst 01:80:c2:00:00:00`.

## 15. Capture filters and display filters are different languages

BPF works in `tcpdump`, `dumpcap -f`, `tshark -f` (live only; ignored with
`-r`), and the Wireshark *capture* filter box. Wireshark's display filters
(`tcp.port == 443`) are a different language and are not BPF. To filter a
file with BPF, use `tcpdump -r` or `tools/capread.py`.

## 16. Comparisons are unsigned 32-bit; loads are big-endian

`ip[2:2] - 100 > 0` wraps around instead of going negative. Fields stored
little-endian, such as DNP3 addresses or EtherNet/IP commands, must be
compared byte-swapped: DNP3 destination 1024 (0x0400) is `... + 4:2] = 0x0004`.

## 17. Older libpcap versions

`icmp6[...]`, `icmp6type`, `ip6 protochain` and some keywords only exist in
newer libpcap releases. For portable filters, prefer `ip6[6] = 58 and
ip6[40] = N` and plain byte offsets. Check with `tcpdump -d 'FILTER'` on the
target machine.
