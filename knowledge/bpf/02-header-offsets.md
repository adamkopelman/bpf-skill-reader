# Header offsets for writing `proto[offset]` filters

All multi-byte fields are big-endian. Offsets are relative to the base that
the `proto[...]` keyword uses.

## Ethernet II (`ether[...]`, frame start)

| Offset | Size | Field |
|---|---|---|
| 0 | 6 | destination MAC (`ether[0] & 1` = group/multicast bit) |
| 6 | 6 | source MAC (OUI = `ether[6:2]` and `ether[8]`) |
| 12 | 2 | EtherType (0x0800 IPv4, 0x86dd IPv6, 0x0806 ARP, 0x8100/0x88a8 VLAN, 0x88cc LLDP, 0x888e EAPOL, 0x8847 MPLS, 0x8892 PROFINET, 0x88b8 IEC 61850 GOOSE, 0x88ba SV); values <= 1500 are 802.3 length (LLC follows) |
| 14 | ... | payload |

## 802.1Q / 802.1ad VLAN tag (inserted at offset 12)

| Offset | Size | Field |
|---|---|---|
| 12 | 2 | TPID 0x8100 (or 0x88a8 / 0x9100 for an outer QinQ tag) |
| 14 | 2 | TCI: PCP = `ether[14] >> 5`, DEI = `ether[14] & 0x10`, VID = `ether[14:2] & 0x0fff` |
| 16 | 2 | inner EtherType (or another TPID for QinQ: next TCI at 18) |

After the `vlan` keyword, `ip[...]`, `tcp[...]` and the others are
automatically shifted by 4 bytes per tag, so you don't add 4 yourself.
`ether[...]` is never shifted.

## Linux cooked capture (`-i any`)

- **SLL v1** (link type 113): 16-byte header. Packet type at 0-1 (0 = to us,
  4 = outgoing), address at 6-13, protocol (EtherType) at 14-15.
- **SLL2** (link type 276): 20-byte header. Protocol at 0-1, interface index
  at 4-7.
- There is no Ethernet header and VLAN tags are removed, so `ether host` and
  `vlan` cannot work.

## IPv4 (`ip[...]`)

| Offset | Size | Field | Typical expression |
|---|---|---|---|
| 0 | 1 | version (high nibble) and IHL in 32-bit words (low nibble) | `ip[0] & 0x0f > 5` (options present) |
| 1 | 1 | DSCP (6 bits) and ECN (2 bits) | `ip[1] >> 2 = 46` (EF) ; `ip[1] & 0x03 = 3` (CE) |
| 2 | 2 | total length | `ip[2:2] > 1400` |
| 4 | 2 | identification | |
| 6 | 2 | flags and fragment offset: 0x4000 DF, 0x2000 MF, `& 0x1fff` offset | `ip[6] & 0x40 != 0` (DF) ; `ip[6:2] & 0x3fff != 0` (any fragment) |
| 8 | 1 | TTL | `ip[8] < 5` |
| 9 | 1 | protocol (1 ICMP, 2 IGMP, 6 TCP, 17 UDP, 47 GRE, 50 ESP, 51 AH, 89 OSPF, 132 SCTP) | |
| 10 | 2 | header checksum | |
| 12 | 4 | source address | `ip[12:4] = 0x0a000001` (10.0.0.1) |
| 16 | 4 | destination address | `ip[16] >= 224` (multicast) |
| 20 | ... | options (if IHL > 5), then transport header at `(ip[0] & 0x0f) * 4` | |

## IPv6 (`ip6[...]`)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | version (4 bits), traffic class (8), flow label (20). Traffic class: `(ip6[0:2] >> 4) & 0xff` |
| 4 | 2 | payload length |
| 6 | 1 | next header (0 hop-by-hop, 6 TCP, 17 UDP, 43 routing, 44 fragment, 58 ICMPv6, 60 dest-opts) |
| 7 | 1 | hop limit |
| 8 | 16 | source address (`ip6[8:4]` is its first 32 bits) |
| 24 | 16 | destination address (`ip6[24] = 0xff` means multicast) |
| 40 | ... | next header's start, **only when there are no extension headers** |

BPF cannot loop, so libpcap does not walk IPv6 extension headers. The only
exception is that `tcp`, `udp` and `ip6 proto` also look one Fragment header
deep. Port filters and `ip6[40...]` both assume the transport header sits at
byte 40.

## TCP (`tcp[...]`, IPv4 only; for IPv6 use `ip6[40 + n]`)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | source port |
| 2 | 2 | destination port |
| 4 | 4 | sequence number |
| 8 | 4 | acknowledgement number |
| 12 | 1 | data offset (high nibble, 32-bit words). Header length in bytes = `(tcp[12] & 0xf0) >> 2` |
| 13 | 1 | flags: CWR 0x80, ECE 0x40, URG 0x20, ACK 0x10, PSH 0x08, RST 0x04, SYN 0x02, FIN 0x01 (`tcp[tcpflags]`) |
| 14 | 2 | window |
| 16 | 2 | checksum |
| 18 | 2 | urgent pointer |
| 20 | ... | options, then payload |

**Payload start:** don't hard-code `tcp[20]`, because SYNs and most modern
stacks send options. Use these forms:

```
tcp[((tcp[12:1] & 0xf0) >> 2) + N]                         IPv4, payload byte N
tcp[((tcp[12:1] & 0xf0) >> 2):4]                           IPv4, first 4 payload bytes
ip6[40 + ((ip6[52] & 0xf0) >> 2) + N]                      IPv6 without extension headers (52 = 40 + 12)
ip6[6] = 6 and ip6[40 + ((ip6[52] & 0xf0) >> 2):4] = ...   always guard with next header = TCP
```

## UDP (`udp[...]`, IPv4 only)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | source port |
| 2 | 2 | destination port |
| 4 | 2 | length |
| 6 | 2 | checksum |
| 8 | ... | payload (`udp[8 + N]`). For IPv6: `ip6[48 + N]` with `ip6[6] = 17` |

## ICMP (`icmp[...]`) / ICMPv6 (`ip6[40...]` or `icmp6[...]`)

- **ICMP:** type at offset 0 (`icmp[icmptype]`) and code at 1. Echo
  identifier at 4-5 and sequence at 6-7.
  - Types: 0 echo reply, 3 unreachable (code 3 port, 4 frag-needed, 13
    admin-prohibited), 5 redirect, 8 echo, 11 time exceeded.
- **ICMPv6:** type at 0, code at 1.
  - Types: 1 unreachable, 2 packet too big, 3 time exceeded, 128/129 echo,
    133 RS, 134 RA, 135 NS, 136 NA, 137 redirect, 143 MLDv2 report.
  - Portable form: `ip6[6] = 58 and ip6[40] = 135`.

## ARP (`arp[...]`)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | hardware type (1 = Ethernet) |
| 2 | 2 | protocol type (0x0800) |
| 4 | 1 | hardware length |
| 5 | 1 | protocol length |
| 6 | 2 | operation: 1 request, 2 reply |
| 8 | 6 | sender MAC |
| 14 | 4 | sender IP (`arp src host`) |
| 18 | 6 | target MAC |
| 24 | 4 | target IP (`arp dst host`) |

Gratuitous ARP: `arp and arp[14:4] = arp[24:4]`.

## Application headers (offsets inside the L4 payload)

Write `P(n)` for the payload byte at offset n. Over IPv4 that is
`udp[8 + n]` for UDP and `tcp[((tcp[12:1] & 0xf0) >> 2) + n]` for TCP.

| Protocol | Port | Field | Payload offset | Filter |
|---|---|---|---|---|
| DNS | udp 53 | ID | 0-1 | |
| DNS | udp 53 | flags (QR bit) | 2 (QR = 0x80) | `udp[10] & 0x80 = 0` (query) |
| DNS | udp 53 | opcode | 2 (`>> 3 & 0x0f`) | |
| DNS | udp 53 | RCODE | 3 (`& 0x0f`) | `udp[11] & 0x0f = 3` (NXDOMAIN) |
| DNS | udp 53 | QDCOUNT | 4-5 | |
| DNS | udp 53 | ANCOUNT | 6-7 | `udp[14:2] = 0` (empty answer) |
| DNS | udp 53 | QNAME | from 12 | variable length, so BPF can only test fixed bytes |
| TLS | tcp 443 etc. | content type | 0 (0x16 handshake, 0x17 data, 0x15 alert, 0x14 CCS) | |
| TLS | tcp 443 etc. | version | 1-2 | |
| TLS | tcp 443 etc. | record length | 3-4 | |
| TLS | tcp 443 etc. | handshake type | 5 (1 ClientHello, 2 ServerHello, 11 Certificate) | `P(0)=0x16 and P(5)=0x01` |
| HTTP/1.x | tcp 80 etc. | first 4 bytes | 0-3 | see the table below |
| SSH | tcp 22 | banner | 0-3 | `"SSH-"` = 0x5353482d |
| SMB2/3 | tcp 445 | magic, after the 4-byte NetBIOS header | 4-7 | 0xfe534d42 (`\xfeSMB`); SMB1 is 0xff534d42 |
| RDP / S7comm / ISO-TSAP | tcp 3389 / 102 | TPKT | 0-1 | 0x0300 |
| S7comm | tcp 102 | protocol id, after TPKT(4) + COTP DT(3) | 7 | 0x32 |
| S7comm | tcp 102 | ROSCTR | 8 | 1 job, 3 ack-data, 7 userdata |
| Modbus/TCP | tcp 502 | MBAP transaction id | 0-1 | |
| Modbus/TCP | tcp 502 | protocol id | 2-3 | 0 |
| Modbus/TCP | tcp 502 | length | 4-5 | |
| Modbus/TCP | tcp 502 | unit id | 6 | |
| Modbus/TCP | tcp 502 | function code | 7 | see below |
| DNP3 | tcp/udp 20000 | start bytes | 0-1 | 0x0564 |
| DNP3 | tcp/udp 20000 | length | 2 | |
| DNP3 | tcp/udp 20000 | link control | 3 | |
| DNP3 | tcp/udp 20000 | destination address | 4-5 | little-endian! |
| DNP3 | tcp/udp 20000 | source address | 6-7 | little-endian! |
| IEC 60870-5-104 | tcp 2404 | start byte | 0 | 0x68 |
| IEC 60870-5-104 | tcp 2404 | APDU length | 1 | |
| IEC 60870-5-104 | tcp 2404 | control field 1 | 2 | `P(2) & 0x01 = 0` I-frame; `P(2) & 0x03 = 1` S-frame; `P(2) & 0x03 = 3` U-frame |
| BACnet/IP | udp 47808 | BVLC type | 0 | 0x81 |
| BACnet/IP | udp 47808 | BVLC function | 1 | |
| EtherNet/IP | tcp 44818 / udp 2222 | encapsulation command | 0-1 | little-endian, e.g. 0x6f00 = SendRRData |
| OPC UA | tcp 4840 | message type | 0-2 | "HEL", "ACK", "OPN", "MSG", "CLO" |
| SNMP | udp 161/162 | BER SEQUENCE | 0 | 0x30 |
| NTP | udp 123 | mode | 0 (`& 0x07`) | 3 client, 4 server, 6 control, 7 private (monlist) |
| DHCP/BOOTP | udp 67/68 | op | 0 | 1 request, 2 reply |
| Syslog | udp 514 | priority | 0 | `"<"` = 0x3c |

HTTP/1.x first 4 bytes:

| Text | Hex |
|---|---|
| `"GET "` | 0x47455420 |
| `"POST"` | 0x504f5354 |
| `"PUT "` | 0x50555420 |
| `"HEAD"` | 0x48454144 |
| `"DELE"` | 0x44454c45 |
| `"OPTI"` | 0x4f505449 |
| `"HTTP"` (response) | 0x48545450 |

Modbus function codes:

| Code | Meaning |
|---|---|
| 1, 2, 3, 4 | reads |
| 5 | write single coil |
| 6 | write single register |
| 15 | write multiple coils |
| 16 | write multiple registers |
| 23 | read/write multiple registers |
| 43 | device identification |
| + 0x80 | exception response |

To convert text to hex offline, run
`python3 -c "print(b'GET '.hex())"` (prints 47455420).
