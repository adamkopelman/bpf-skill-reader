# Offline BPF knowledge base

This is self-contained reference material for writing, checking and deploying
BPF (tcpdump/libpcap) capture filters without internet access. The claims in
these files were verified against tcpdump 4.99.4 / libpcap 1.10.4 and against
this repo's own engine. `tools/check_docs.py` re-checks every filter in the
recipe blocks.

| File | Use it when |
|---|---|
| [01-filter-syntax.md](01-filter-syntax.md) | writing any filter: primitives, qualifiers, operators, byte relations, named constants |
| [02-header-offsets.md](02-header-offsets.md) | you need `proto[offset]`: Ethernet/VLAN/SLL/IPv4/IPv6/TCP/UDP/ICMP/ARP layouts and application-layer offsets (DNS, TLS, HTTP, SMB, Modbus, DNP3, S7, IEC-104, BACnet, ...) |
| [03-recipes.md](03-recipes.md) | you want a ready-made filter, or need to deploy one (tcpdump, Wireshark, tshark, iptables) |
| [04-gotchas.md](04-gotchas.md) | a filter behaves unexpectedly, or before you trust a hand-written one |
| [05-classic-bpf.md](05-classic-bpf.md) | reading `tcpdump -d` output, generating bytecode, attaching filters to sockets/iptables |
| [06-capture-files.md](06-capture-files.md) | identifying a `.cap` file, link types, converting formats |
| [07-air-gapped-operations.md](07-air-gapped-operations.md) | moving this repo into an enclave, verifying it, and working there day to day |

The five rules that cause most filter bugs:

1. `and` and `or` have **equal** precedence. Parenthesise.
2. `vlan` shifts all later offsets. Write `X or (vlan and X)`, never `(vlan and X) or X`.
3. `tcp[]`/`udp[]`/`icmp[]` are IPv4-only. For IPv6, use `ip6[40 + n]` with an `ip6[6] = proto` guard.
4. Compute the TCP payload start with `((tcp[12:1] & 0xf0) >> 2)`. Never hard-code 20.
5. No DNS offline. Use IP addresses and port numbers, and run tcpdump with `-nn`.
