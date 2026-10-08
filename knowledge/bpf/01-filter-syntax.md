# BPF / pcap-filter syntax reference (offline)

This is the language accepted by `tcpdump`, `libpcap`, `dumpcap`/`tshark -f`,
the Wireshark *capture* filter box, and this repo's `tools/capread.py`. It is
not the same as the Wireshark *display* filter language (`ip.addr == 1.2.3.4`).

An expression is a combination of **primitives**. A packet is accepted when the
expression is true. An empty expression accepts every packet.

---

## 1. Primitives = [proto] [dir] [type] value

| Qualifier | Values | Default when omitted |
|---|---|---|
| **type** | `host`, `net`, `port`, `portrange` (also `gateway`, `proto`, `protochain`) | `host` |
| **dir** | `src`, `dst`, `src or dst`, `src and dst` | `src or dst` |
| **proto** | `ether`, `ip`, `ip6`, `arp`, `rarp`, `tcp`, `udp`, `sctp`, `icmp`, `icmp6`, `igmp`, `pim`, `vrrp`, `ah`, `esp`, `link` | every protocol that fits the type |

```
host 10.1.2.3            src host 10.1.2.3         dst host 2001:db8::1
net 10.0.0.0/8           net 10.0.0.0 mask 255.0.0.0     net 10      (= 10.0.0.0/8)
net 192.168              (= 192.168.0.0/16)        src net 172.16.0.0/12
port 53                  tcp port 443              udp dst port 161
portrange 1-1023         tcp src portrange 49152-65535
ether host 00:11:22:33:44:55    ether src 0011.2233.4455   ether dst ff:ff:ff:ff:ff:ff
ip host 10.1.2.3         (IPv4 only, no ARP)       arp host 10.1.2.3 (ARP sender/target)
ip6 net 2001:db8::/32
```

- `host` with an IPv4 address also matches **ARP and RARP** sender/target
  addresses. Use `ip host` for IP only.
- `port` matches TCP, UDP and SCTP, on IPv4 and IPv6. Use `tcp port` or `udp port`
  to narrow it.
- `net` with an abbreviated address (`net 10`, `net 172.16`) uses the implied mask (/8, /16, /24).
  Host bits must be zero: `net 10.0.0.1/8` is an error.
- Port and service names (`port http`, `port domain`, `port ftp-data`) come from
  `/etc/services`. capread has a built-in table, but numbers always work. Prefer
  numbers on air-gapped hosts.
- Hostnames (`host server1`) need name resolution. **Use IP addresses on
  air-gapped systems.**
- MAC addresses: `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`.

## 2. Protocol primitives (no value)

| Primitive | Meaning |
|---|---|
| `ip`, `ip6`, `arp`, `rarp` | EtherType 0x0800 / 0x86dd / 0x0806 / 0x8035 (or link-type equivalent) |
| `tcp`, `udp`, `sctp` | IPv4 protocol or IPv6 next header (also checked behind one IPv6 Fragment header) |
| `icmp`, `igmp`, `vrrp` | IPv4 protocol 1 / 2 / 112 |
| `icmp6` | IPv6 next header 58 |
| `pim`, `ah`, `esp` | IPv4 or IPv6 protocol 103 / 51 / 50 |
| `ip proto N`, `ip6 proto N`, `proto N` | protocol number, or a name with a backslash: `ip proto \tcp` |
| `ether proto N` | EtherType, e.g. `ether proto 0x88cc` (LLDP), `ether proto \arp` |
| `vlan [id]` | 802.1Q/802.1ad tag present (TPID 0x8100, 0x88a8, 0x9100), optionally with VLAN id. **Shifts later offsets by 4: see gotchas.** |
| `mpls [label]`, `pppoes [sess]` | similar encapsulation keywords (tcpdump only) |
| `broadcast` / `ether broadcast` | destination MAC ff:ff:ff:ff:ff:ff |
| `multicast` / `ether multicast` | destination MAC group bit set (includes broadcast) |
| `ip broadcast` | IPv4 broadcast destination (needs the netmask, so offline only 255.255.255.255 / 0.0.0.0) |
| `ip multicast` | IPv4 destination 224.0.0.0/4 and above (`ip[16] >= 224`) |
| `ip6 multicast` | IPv6 destination ff00::/8 |
| `less N` | `len <= N` |
| `greater N` | `len >= N` |

## 3. Combining

| Operator | Alternatives |
|---|---|
| `and` | `&&` |
| `or` | `\|\|` |
| `not` | `!` |
| grouping | `( ... )` (quote the whole filter in the shell) |

**Precedence:** `not` binds tightest. **`and` and `or` have EQUAL precedence and
associate left to right**, unlike C:

```
host 10.0.0.53 and port 53 or icmp        ==  (host 10.0.0.53 and port 53) or icmp      # 12 packets in demo.pcap
host 10.0.0.53 and (port 53 or icmp)                                                    #  6 packets
a or b and c                              ==  (a or b) and c                             # NOT a or (b and c)
```

**Value carry-over:** a bare value reuses the previous primitive's qualifiers:

```
tcp dst port 21 or 22 or 23        ==  tcp dst port 21 or tcp dst port 22 or tcp dst port 23
host 10.0.0.1 or 10.0.0.2          ==  host 10.0.0.1 or host 10.0.0.2
not host 10.0.0.1 or 10.0.0.2      ==  (not host 10.0.0.1) or host 10.0.0.2     # careful
```

A bare value with nothing to inherit (`10.0.0.1` alone) is a syntax error.

## 4. Byte-level relations

```
proto [ offset ]            1 byte
proto [ offset : size ]     size = 1, 2 or 4 bytes, big-endian (network order)
```

`proto` is one of `ether`/`link` (start of the frame), `ip`, `ip6`, `arp`, `rarp`,
`tcp`, `udp`, `icmp`, `igmp`, `sctp`, `pim`, `vrrp`, `icmp6`. `offset` is an
arithmetic expression that may itself contain loads.

- `ip[...]` and `ip6[...]` count from the start of the IP header.
- `tcp[...]`, `udp[...]`, `icmp[...]` and the other transport protocols count
  from the start of the transport header. **They work on IPv4 packets only, and
  only on the first fragment.** The IPv4 header length is computed for you.
- `icmp6[...]` counts from IPv6 byte 40, and only when the next header is 58
  (needs a recent libpcap).
- A relation that indexes a protocol is **false** for packets of other
  protocols. So `ip[9] = 6` is false for ARP, and `not ip[9] = 6` is true for
  ARP.

Relations compare two arithmetic expressions:

```
expr  relop  expr        relop: =  ==  !=  <  >  <=  >=        (unsigned 32-bit)
```

| Operator | Notes |
|---|---|
| `\|` | lowest arithmetic precedence |
| `^` | |
| `&` | |
| `<<` `>>` | |
| `+` `-` | |
| `*` `/` `%` | highest |

`len` is the original (wire) length of the packet. Numbers can be decimal, hex
`0x1f` or octal `017`.

Named constants:

| Name | Value |
|---|---|
| `tcpflags` | 13 |
| `tcp-fin` `tcp-syn` `tcp-rst` `tcp-push` `tcp-ack` `tcp-urg` `tcp-ece` `tcp-cwr` | 0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 |
| `icmptype` / `icmpcode` | 0 / 1 |
| `icmp-echoreply` `icmp-unreach` `icmp-sourcequench` `icmp-redirect` `icmp-echo` `icmp-routeradvert` `icmp-routersolicit` `icmp-timxceed` `icmp-paramprob` `icmp-tstamp` `icmp-tstampreply` `icmp-ireq` `icmp-ireqreply` `icmp-maskreq` `icmp-maskreply` | 0 3 4 5 8 9 10 11 12 13 14 15 16 17 18 |
| `icmp6type` / `icmp6code` | 0 / 1 |
| `icmp6-echo` `icmp6-echoreply` `icmp6-routersolicit` `icmp6-routeradvert` `icmp6-neighborsolicit` `icmp6-neighboradvert` `icmp6-redirect` | 128 129 133 134 135 136 137 |

```
tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn          # pure SYN
icmp[icmptype] = icmp-echo                           # ping request
ip[0] & 0x0f > 5                                     # IPv4 header has options
ip[6:2] & 0x1fff != 0                                # non-first fragment
tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420        # TCP payload starts with "GET "
udp[8:2] = 0x1234                                    # first 2 bytes of UDP payload
ether[0] & 1 = 1                                     # multicast/broadcast destination
```

## 5. Quoting and files

- Always single-quote the whole filter in the shell: `tcpdump -r f.pcap 'tcp[13] & 2 != 0'`.
  Otherwise `[`, `&`, `!` and `(` get interpreted by the shell.
- Long filters can live in a file. `tcpdump -F file.bpf` reads them (it does
  not accept comments). `capread.py -F file.bpf` also accepts `#` comments.
- Put spaces around arithmetic minus (`len - 54`). `len-54` is read as one word.
