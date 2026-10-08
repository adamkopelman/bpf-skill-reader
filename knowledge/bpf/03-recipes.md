# BPF recipes (offline cookbook)

Every line in a `bpf` block below has been compiled by tcpdump 4.99 / libpcap
1.10 and by `bpfkit` (see `tools/check_docs.py`). Text after `#` is a comment;
don't paste it into tcpdump. Replace the example addresses and ports with yours.

## Hosts, networks, conversations

```bpf
host 10.0.0.5                                         # anything to/from (IPv4 + ARP)
ip host 10.0.0.5                                      # IPv4 only, no ARP
src host 10.0.0.5 and dst net 10.20.0.0/16            # one direction
host 10.0.0.5 and host 10.0.0.9                       # the conversation between two hosts
host 10.0.0.5 and not host 10.0.0.9                   # host's traffic except with .9
net 10.0.0.0/8 and not net 10.20.0.0/16
not net 10.0.0.0/8 and not net 172.16.0.0/12 and not net 192.168.0.0/16   # leaves the RFC1918 space (IPv4)
ip6 and not ip6 net fe80::/10                         # IPv6 except link-local
ether host 00:11:22:33:44:55                          # by MAC (works for non-IP too)
ether src 00:11:22:33:44:55 and not ip and not arp    # a device's non-IP traffic
ether[6:2] = 0x0011 and ether[8] = 0x22               # source MAC OUI 00:11:22 (vendor)
```

## Ports and services

```bpf
tcp port 443                                          # HTTPS
udp port 53 or tcp port 53                            # DNS over UDP and TCP
tcp dst port 22 or 3389 or 5900                       # carry-over: dst port 22/3389/5900
tcp portrange 1-1023                                  # well-known TCP ports
udp and not port 53 and not port 123 and not port 67 and not port 68
tcp and not port 22                                   # everything except SSH
not (host 10.0.0.5 and tcp port 22)                   # exclude your own SSH session
udp dst portrange 33434-33534                         # UDP traceroute probes
```

## TCP flags and connection state (IPv4; see gotchas for IPv6)

```bpf
tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn           # connection attempts (SYN only)
tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack) # accepted connections (SYN+ACK)
tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0        # start/end of every connection
tcp[tcpflags] & tcp-rst != 0                          # resets (refused / aborted)
tcp[tcpflags] & tcp-fin != 0                          # closes
tcp[tcpflags] & tcp-push != 0                         # segments carrying pushed data
tcp[tcpflags] = 0                                     # NULL scan
tcp[tcpflags] & (tcp-fin|tcp-push|tcp-urg) = (tcp-fin|tcp-push|tcp-urg)   # Xmas scan
tcp[tcpflags] & (tcp-syn|tcp-fin) = (tcp-syn|tcp-fin) # SYN+FIN (always malicious)
tcp[tcpflags] = tcp-fin                               # FIN scan (FIN alone, no ACK)
tcp[14:2] = 0 and tcp[tcpflags] & tcp-rst = 0         # zero window (receiver stalled)
tcp and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0) >> 2)) != 0)   # TCP with payload (IPv4)
tcp[tcpflags] & (tcp-ece|tcp-cwr) != 0                # ECN signalling (libpcap >= 1.9)
tcp[13] & 0xc0 != 0                                   # ECN signalling, any libpcap (RHEL 7 too)
```

## ICMP / ICMPv6

```bpf
icmp[icmptype] = icmp-echo or icmp[icmptype] = icmp-echoreply   # ping
icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply  # ICMP errors etc.
icmp[icmptype] = icmp-unreach and icmp[icmpcode] = 4  # fragmentation needed (PMTUD)
icmp[icmptype] = icmp-timxceed                        # traceroute replies / loops
ip6[6] = 58 and (ip6[40] = 128 or ip6[40] = 129)      # ping6
ip6[6] = 58 and ip6[40] >= 133 and ip6[40] <= 137     # NDP (RS/RA/NS/NA/redirect)
ip6[6] = 58 and ip6[40] = 134                         # router advertisements (rogue RA hunting)
icmp6                                                 # all ICMPv6
```

## Fragments, options, odd packets

```bpf
ip[6:2] & 0x3fff != 0                                 # any IPv4 fragment (MF set or offset > 0)
ip[6:2] & 0x1fff != 0                                 # non-first fragments (no ports here!)
ip[6] & 0x40 != 0                                     # Don't Fragment set
ip[0] & 0x0f > 5                                      # IPv4 header options present
ip[8] < 5                                             # very low TTL (traceroute, loops)
ip6[6] = 44                                           # IPv6 fragment header directly after IPv6
ip6[6] = 0 or ip6[6] = 43 or ip6[6] = 60              # IPv6 extension headers present
ip and ip[12:4] = ip[16:4]                            # LAND attack (src == dst)
greater 1500                                          # jumbo/oversized frames
less 64                                               # runts / tiny frames
```

## Broadcast, multicast, link-layer noise

```bpf
ether broadcast                                       # L2 broadcast
ether multicast and not ether broadcast               # L2 multicast only
not ether broadcast and not ether multicast           # unicast frames only
ip multicast                                          # IPv4 multicast destinations
ip6 multicast                                         # IPv6 multicast destinations
arp                                                   # all ARP
arp and arp[6:2] = 2                                  # ARP replies
arp and arp[14:4] = arp[24:4]                         # gratuitous ARP
ether proto 0x88cc                                    # LLDP
ether dst 01:80:c2:00:00:00                           # STP BPDUs
ether proto 0x888e                                    # 802.1X EAPOL
not arp and not ether multicast and not ether broadcast   # drop LAN chatter
```

## VLANs (read gotchas: `vlan` shifts later offsets)

```bpf
vlan                                                  # any tagged frame
vlan 20                                               # VLAN 20
vlan 20 and host 10.20.0.5                            # host inside VLAN 20
vlan and vlan 200                                     # QinQ, inner VLAN 200
ip or (vlan and ip)                                   # IPv4 tagged or untagged (order matters!)
tcp port 80 or (vlan and tcp port 80)                 # same idea for a port
ether[12:2] = 0x8100 and ether[14:2] & 0x0fff = 20    # VLAN 20 without shifting (FILES ONLY: never matches live on Linux receive)
```

## Application protocols (IPv4 payload offsets)

```bpf
udp port 53 and udp[10] & 0x80 = 0                    # DNS queries
udp port 53 and udp[10] & 0x80 != 0                   # DNS responses
udp port 53 and udp[11] & 0x0f = 3                    # DNS NXDOMAIN
udp port 53 and udp[11] & 0x0f != 0                   # DNS errors
tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420    # HTTP GET
tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354    # HTTP POST
tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450                    # HTTP responses, any port
tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16 and tcp[((tcp[12:1] & 0xf0) >> 2) + 5] = 0x01   # TLS ClientHello, any port
tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x5353482d                    # SSH banner, any port
tcp port 445 and tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0xff534d42   # SMBv1 (should be gone)
udp port 123 and udp[8] & 0x07 = 7                    # NTP mode 7 (monlist abuse)
udp port 161 and udp[8] = 0x30                        # SNMP
udp and (port 67 or port 68)                          # DHCP
udp port 514                                          # syslog
udp port 1900                                         # SSDP
udp port 5353                                         # mDNS
```

## Industrial / OT protocols (common in air-gapped networks)

```bpf
tcp port 502                                          # Modbus/TCP
tcp port 502 and tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 6                    # Modbus write single register
tcp port 502 and (tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 5 or tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 6 or tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 15 or tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 16)   # all Modbus writes
tcp port 502 and tcp[((tcp[12:1] & 0xf0) >> 2) + 7] & 0x80 != 0            # Modbus exception responses
tcp port 502 and tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 43                   # Modbus device identification (recon)
tcp port 20000 and tcp[((tcp[12:1] & 0xf0) >> 2):2] = 0x0564               # DNP3 frames over TCP
udp port 20000 and udp[8:2] = 0x0564                  # DNP3 over UDP
tcp port 102 and tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 0x32                 # Siemens S7comm
tcp port 2404 and tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x68                    # IEC 60870-5-104
udp port 47808 and udp[8] = 0x81                      # BACnet/IP
tcp port 44818 or udp port 44818 or udp port 2222     # EtherNet/IP + CIP I/O
tcp port 4840                                         # OPC UA
ether proto 0x8892                                    # PROFINET RT
ether proto 0x88b8                                    # IEC 61850 GOOSE
ether proto 0x88ba                                    # IEC 61850 Sampled Values
tcp port 502 and not (host 10.0.1.5 and host 10.0.1.20)                    # Modbus from anyone but the known HMI-PLC pair
```

## Scans and reconnaissance

```bpf
src host 10.0.0.66 and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn        # one host's SYN probes
tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and tcp[14:2] = 1024          # nmap-style SYN probe (window 1024)
tcp[tcpflags] & tcp-rst != 0 and tcp[tcpflags] & tcp-ack != 0 and tcp[14:2] = 0   # RST/ACK refusals (closed ports)
icmp[icmptype] = icmp-unreach and icmp[icmpcode] = 3  # UDP closed port replies
icmp[icmptype] = icmp-echo and not src net 10.0.0.0/8  # pings from outside your range
```

## IPv6 payload equivalents (no extension headers)

```bpf
ip6 and tcp port 443                                  # port primitives work for IPv6
ip6[6] = 6 and ip6[53] & 0x12 = 0x02                  # IPv6 SYN only (53 = 40 + 13)
ip6[6] = 6 and ip6[53] & 0x04 != 0                    # IPv6 RST
ip6[6] = 6 and ip6[40 + ((ip6[52] & 0xf0) >> 2):4] = 0x47455420   # IPv6 HTTP GET
ip6[6] = 17 and ip6[42:2] = 53 and ip6[50] & 0x80 = 0 # IPv6 DNS query (42 = dst port, 50 = flags)
```

## Size, TTL, fingerprints

```bpf
len > 1000 and udp                                    # big UDP (amplification, tunnels)
udp and udp[4:2] > 512                                # UDP payload length field > 512
ip[8] = 64 or ip[8] = 128 or ip[8] = 255              # common initial TTLs (OS hints)
tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and tcp[14:2] = 65535   # SYN with window 65535
```

---

## Using a filter

```sh
# offline: read a file (any link type), print or carve
tcpdump -nn -r in.pcap 'FILTER'
tcpdump -nn -r in.pcap -w out.pcap 'FILTER'
python3 tools/capread.py in.pcap 'FILTER' -w out.pcap      # no tcpdump needed

# live capture (needs root/CAP_NET_RAW). -nn: no DNS / port names (air-gapped!)
tcpdump -i eth0 -nn -s 0 -w cap.pcap 'FILTER'
tcpdump -i eth0 -nn -w ring.pcap -C 100 -W 10 'FILTER'     # 10 x 100 MB ring buffer
tcpdump -i eth0 -F filter.bpf -w cap.pcap                  # filter from file (no comments)

# Wireshark: put FILTER in the *capture* filter box (Capture > Options), not the display filter bar
dumpcap -i eth0 -f 'FILTER' -w cap.pcapng
tshark -i eth0 -f 'FILTER' -w cap.pcapng                   # -f is ignored with -r (files): use tcpdump/capread

# check syntax and see the compiled program
tcpdump -d 'FILTER'               # human-readable classic BPF
tcpdump -dd 'FILTER'              # C array of struct sock_filter
tcpdump -ddd 'FILTER'             # decimal (count + "code jt jf k" lines)
tcpdump -d -y RAW 'FILTER'        # compile for packets starting at the IP header

# kernel firewall match (xt_bpf); packets start at the IP header -> compile with -y RAW
iptables -A INPUT -m bpf --bytecode "$(tcpdump -ddd -y RAW 'udp dst port 53' | paste -sd, -)" -j DROP
```

See `05-classic-bpf.md` for attaching the bytecode to sockets yourself.
