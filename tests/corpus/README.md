# Real-capture test corpus

These 29 captures come from the regression suite of the
[tcpdump project](https://www.tcpdump.org/), release 4.99.4 (`tests/` in
`tcpdump-4.99.4.tar.gz`). They are redistributed under tcpdump's BSD licence;
see `LICENSE.tcpdump`.

They were picked to exercise the parts that synthetic traffic misses:
QinQ/VLAN, IPv6 extension headers, IPv4 fragments, IP and TCP options,
snaplen-truncated packets, deliberately malformed "oobr" (out-of-bounds read)
packets, DNS/DHCP/HTTP/SCTP, link types Ethernet / Linux SLL / raw IP /
raw IPv4 / raw IPv6 / BSD NULL, pcapng, and a 64-bit timestamp.

`expected.json` holds what real tcpdump/libpcap selected for each filter, as a
count and digest of the packet numbers. `tools/corpus.py` generates the
filters: a generic set plus filters derived from each capture's own hosts,
ports, MACs and VLANs.

```sh
python3 tools/corpus.py check            # bpfkit vs expected.json (no tcpdump needed; selftest runs it)
python3 tools/corpus.py record           # regenerate expected.json with the local tcpdump
python3 tools/corpus.py xcheck DIR       # live comparison against tcpdump on any captures
```

In development the full tcpdump 4.99.4 suite (399 captures with supported
link types, 8,723 packets) was cross-checked with `xcheck`. It gave 37,978
agreeing comparisons and no unexplained differences. The only differences are
the documented libpcap-optimiser cases (knowledge/bpf/04-gotchas.md §6).
