---
name: bpf-builder
description: Create a BPF (tcpdump/libpcap capture filter) that selects exactly the packets the user wants, by finding the distinguishing pattern in a .cap/.pcap/.pcapng file. Use when the user asks to write, generate, derive, tune or explain a BPF / tcpdump filter / capture filter, wants to isolate or exclude some traffic, says "find the pattern" or "make a filter for these packets", or needs a filter for tcpdump -i, Wireshark capture filters, tshark -f, SO_ATTACH_FILTER or iptables -m bpf. Works offline (air-gapped) with only Python 3.
---

# bpf-builder: find the pattern, generate the BPF, prove it

The tool is `tools/bpfgen.py`, which uses only the Python standard library.
It has three subcommands:

- `profile` describes what is in the capture and gives a ready-made BPF for
  each notable group.
- `suggest` learns the shortest BPF that selects a target set of packets and
  rejects all the others.
- `test` scores any filter against the capture and a target set.

Every suggested filter is re-run through the built-in libpcap-compatible
engine. When tcpdump exists, it is also re-run through tcpdump, so the numbers
reported are measured, not predicted.

Reference material for an offline environment lives in `knowledge/bpf/`. Read
`04-gotchas.md` before you hand-edit any generated filter.

## Workflow

### 1. Pin down the intent

Find out three things before running anything. If the request is ambiguous,
ask:

- **Which packets** should match? Packet numbers, a conversation, a payload
  string, "the scan", "Modbus writes", and so on.
- **What it's for.** Is it for live capture on future traffic, or for
  carving this one file? Future traffic needs the **general** filter, built
  from protocol, address and port terms. Carving this file can use the
  **exact** filter.
- **What must NOT match**, and what doesn't matter either way. ARP and
  broadcast noise are common "don't care" packets.

### 2. Look at the capture

```bash
python3 tools/bpfgen.py profile capture.pcap
python3 tools/capread.py capture.pcap 'some broad filter' -c 40     # see packet numbers
```

`profile` lists the following, each with a BPF that selects it:

- protocols and top hosts
- conversations
- server ports and VLANs
- TCP flag combinations and ICMP types
- MAC addresses and payload prefixes
- DNS names, HTTP lines, TLS SNI and Modbus function codes
- likely port scans

Often the answer is already one of those lines.

### 3. Describe the targets to `suggest`

The selectors can be combined; a packet must satisfy all of them:

| Selector | Example |
|---|---|
| `--packets` | `--packets 40,42,44-54` (numbers as shown by capread or Wireshark) |
| `--where` | `--where 'tcp port 502'` (narrow with a broad BPF) |
| `--contains` | `--contains 'GET /admin'` (payload text) |
| `--contains-hex` | `--contains-hex 0506` (payload bytes) |
| `--flow-of` | `--flow-of 25` (the whole conversation of packet 25, both directions) |
| `--ignore` | `--ignore 'arp or ether broadcast'` (don't care either way) |

```bash
python3 tools/bpfgen.py suggest capture.pcap --packets 40,42,44,46,48,50,52,54
python3 tools/bpfgen.py suggest capture.pcap --where 'tcp port 502' --contains-hex 0006 --ignore arp
```

Useful knobs:

- `--mode exact|general|both` (default `both`)
- `--max-rules N`: how many OR-ed alternatives are allowed
- `--max-terms N`: how many AND-ed terms per alternative
- `--allow-fp 0.05`: accept a few extra packets in exchange for a shorter filter
- `--bytecode`: also show `tcpdump -d` output
- `--json`: machine-readable output

### 4. Read the output critically

`suggest` prints three things:

- **What the targets have in common:** each trait, the share of targets that
  have it, and how many other packets also have it. Use this to reason about
  the pattern and explain it to the user.
- **[exact]:** may use payload bytes, frame length, TTL, TCP window and
  ephemeral ports. It is the best fit for this file.
- **[general]:** uses only protocol, address, port, VLAN, flag, ICMP-type,
  DNS-bit and fragment terms. It is more likely to keep working on new
  traffic.

Each one comes with precision and recall, the extra or missed packet numbers,
and the tcpdump verdict.

Judge the result before presenting it:

- **Overfitting.** Ephemeral source ports, a single TTL value, an exact
  `len = N`, or a payload byte that is really a counter or ID (sequence
  numbers, transaction IDs) won't match future packets. The tool already
  penalises fields that vary within a service, but with only one example it
  cannot know which field the user cares about. Ask for more examples, or use
  `--where` and `--contains` to state the intent.
- **Too broad.** If `[general]` has low precision, say so, and show which
  packets it adds (`bpfgen.py test ... --where/--packets ...`).
- **Readability.** You may rewrite the filter into a clearer equivalent,
  such as `tcp port 502` instead of `port 502 and tcp`, or the named flags
  in `tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn`. Then **re-verify it with
  `test`**. Never hand back an edited filter without re-testing it.

### 5. Verify the final filter

```bash
python3 tools/bpfgen.py test capture.pcap 'FINAL FILTER' --packets <targets>   # TP/FP/FN + offending packets
python3 tools/capread.py capture.pcap 'FINAL FILTER' --stats                  # eyeball what it matches
python3 tools/capread.py capture.pcap 'FINAL FILTER' --check                  # bytecode, if tcpdump exists
```

### 6. Deliver

Give the user:

1. The filter in a code block, ready to paste.
2. One line per term saying why it is there. Use the trait descriptions from
   the output.
3. Measured precision and recall on this capture, and the tcpdump agreement
   if tcpdump is available.
4. How to use it. See `knowledge/bpf/03-recipes.md` § "Using a filter"
   (`tcpdump -i eth0 -w out.pcap 'FILTER'`, `tcpdump -r`, Wireshark capture
   filter, `tshark -f`, `tcpdump -ddd` for `iptables -m bpf` or
   `SO_ATTACH_FILTER`).
5. Caveats that apply. Most often: VLAN-tagged traffic on live captures,
   because Linux strips tags (gotcha 3). Also the libpcap version on the target
   sensor: RHEL 7's 1.5.3 lacks `tcp-ece`/`tcp-cwr` and `icmp6[...]`, and
   handles live `vlan` differently (`knowledge/bpf/08-libpcap-versions.md`).
   Also IPv6 coverage when the filter uses `tcp[...]`, and payload offsets
   that assume no IP/TCP options when hand-written.

If the user wants the filter saved, write it to a `.bpf` file with a `#`
comment header. `capread.py -F file.bpf` and `tcpdump -F file.bpf` (without
the comment lines) can read it.

## How it works (for explaining limits)

- **Candidate terms.** Every packet is decoded and turned into candidate
  terms: protocols, src/dst/either host, /24 and /16 nets, IPv6 /64, ports
  (proto-qualified and directional), VLAN IDs, TCP flags, ICMP types, the DNS
  QR bit, fragments, MACs, TTL, TCP window, payload bytes 0-15 and 2/4-byte
  words, length bounds, and `not X` refinements. Each term is written as BPF
  with exactly libpcap's semantics.
- **Learning.** Sequential covering with FOIL gain builds OR-ed rules of
  AND-ed terms. Cost weights prefer readable and generalisable terms. Each
  rule is then pruned of redundant terms.
- **Rendering.** The renderer follows libpcap's quirks. It fully
  parenthesises, groups all rules that live inside VLAN tags under a single
  trailing `vlan` (because each `vlan` shifts later offsets), and puts
  payload-indexing rules last (because an out-of-range load rejects the
  packet).
- **What BPF cannot do.** It cannot search for a string at a variable offset,
  parse DNS names, follow TCP streams, or match TLS SNI. If the user asks for
  that, explain it and offer the closest BPF, such as the server, port and
  message type, plus post-filtering with `capread.py`.
