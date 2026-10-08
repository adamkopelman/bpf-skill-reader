# bpf-skill-reader

This repo has Claude Code skills and offline tooling for **reading `.cap`
capture files with a BPF filter** and **generating a BPF that selects exactly
the packets you want**. It is built for **air-gapped systems**: it needs only
Python 3 (>= 3.5) and has no pip packages, no tcpdump and no network
dependency.

| Piece | What it does |
|---|---|
| `.claude/skills/cap-reader/` | Skill: open and inspect .cap/.pcap/.pcapng, filter with BPF, carve subsets |
| `.claude/skills/bpf-builder/` | Skill: find the pattern behind the packets you point at and generate + verify a BPF |
| `tools/capread.py` | CLI: tcpdump-like reader with a built-in libpcap-compatible filter engine |
| `tools/bpfgen.py` | CLI: `profile` (what's in a capture), `suggest` (learn a BPF), `test` (score a BPF) |
| `tools/selftest.py` | proves the engine on this host against recorded tcpdump/libpcap results |
| `knowledge/bpf/` | offline BPF reference: syntax, header offsets, recipes (IT + OT/ICS), gotchas, cBPF bytecode, file formats, air-gapped ops |
| `samples/demo.pcap` | a small synthetic capture (DNS, HTTP, TLS, ICMP, Modbus/TCP, a port scan, VLAN, IPv6, fragments) |

## Quick start

```sh
python3 tools/selftest.py                                   # RESULT: PASS

# read
python3 tools/capread.py samples/demo.pcap --info
python3 tools/capread.py samples/demo.pcap 'tcp port 502 and host 10.0.1.5'
python3 tools/capread.py samples/demo.pcap 'udp port 53' -v
python3 tools/capread.py samples/demo.pcap 'icmp' --stats
python3 tools/capread.py samples/demo.pcap 'vlan 20' -w vlan20.pcap

# find a pattern and build a filter for it
python3 tools/bpfgen.py profile samples/demo.pcap
python3 tools/bpfgen.py suggest samples/demo.pcap --packets 40,42,44,46,48,50,52,54   # the port scan
python3 tools/bpfgen.py suggest samples/demo.pcap --packets 36                        # the Modbus write
python3 tools/bpfgen.py suggest samples/demo.pcap --contains 'GET /firmware'
python3 tools/bpfgen.py test samples/demo.pcap 'tcp port 502' --where 'tcp[tcpflags] & tcp-push != 0'
```

For example, `suggest --packets 36` finds the one Modbus "write single
register" request among 69 packets:

```
  [exact]  src host 10.0.1.5 and tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 0x06
      selects 1 packets: 1/1 targets (recall 100%), 0 other packets (precision 100%)
          src host 10.0.1.5                                            src address
          tcp[((tcp[12:1] & 0xf0) >> 2) + 7] = 0x06                    payload byte 7 = 0x06 (.)
      tcpdump agrees (1 packets)
```

## Using it with Claude Code

Start Claude Code in this directory and ask in plain language:

- "Read capture.cap and show me only the DNS responses from 10.0.0.53"
- "Make me a BPF that catches the port scan in capture.cap but nothing else"
- "Packets 120-140 are the firmware upload; give me a capture filter for that
  traffic that I can put on the sensor"

The skills tell Claude how to run the tools, how to verify every filter, and
which knowledge files to consult.

## How faithful is the filter engine?

`bpfkit/bpf.py` reimplements the libpcap filter language as an interpreter
over raw packet bytes. It copies libpcap's quirks: equal `and`/`or`
precedence, qualifier carry-over, `vlan` offset shifting, IPv4-only
`tcp[]`/`udp[]`, and out-of-bounds rejection.

- During development, 182 filter/link-type cases and the 115 recipes in
  `knowledge/bpf/03-recipes.md` were compared packet-for-packet with tcpdump
  4.99.4 / libpcap 1.10.4 and all of them agree.
- The two known differences are documented in `knowledge/bpf/04-gotchas.md`:
  libpcap's optimiser sometimes skips an out-of-range load, and libpcap's
  unary minus is broken.

Supported link types are Ethernet, raw IP, Linux SLL/SLL2 and BSD
NULL/LOOP. Unsupported constructs, such as Wi-Fi, `mpls` or `protochain`,
produce a clear error that suggests tcpdump.

## Plan and known weaknesses

See [ROADMAP.md](ROADMAP.md) for the prioritised plan and the honest list
of what needs to get better: real-capture test corpus, older Python and
libpcap verification, bytecode output, learner and VLAN limitations, and
skill evals.

## Development

```sh
python3 tools/selftest.py        # engine + formats + bpfgen (uses tcpdump too when installed)
python3 tools/check_docs.py      # every recipe filter compiles (and matches tcpdump when installed)
python3 -m bpfkit.synth samples/demo.pcap   # regenerate the demo capture
```

The code is standard-library only and must stay compatible with Python 3.5+.
If you change `bpfkit/synth.py`, regenerate `bpfkit/expected.py` with tcpdump.
