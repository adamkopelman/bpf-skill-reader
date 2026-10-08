# Roadmap: plan and known weaknesses

This is an honest list of what works today, what is weak, and what to do
next, in priority order. Each item names the files involved and how to know
it is done.

## Where things stand (after Phase 1)

| Area | State |
|---|---|
| Capture reading | pcap (µs/ns/modified), pcapng, snoop, gzip. Ethernet, raw IP, SLL/SLL2, NULL/LOOP |
| Filter engine | libpcap-compatible interpreter. Agrees with tcpdump 4.99.4 / libpcap 1.10.4 on the whole tcpdump test suite (399 real captures, 37,978 comparisons) and with libpcap 1.9.1 and 1.10.0 on the committed corpus |
| Pattern mining | `bpfgen profile/suggest/test`. Greedy rule learner with tcpdump-verified output. 400 mangled captures fuzzed, 0 crashes |
| Knowledge base | 8 offline reference files. 119 recipe filters machine-checked, also on libpcap 1.5.3 to 1.10.0 |
| Verification | `tools/selftest.py`: synthetic results, 2,681 real-capture checks and 40 unit tests, all offline. Plus `tools/check_docs.py`, `tools/corpus.py` and CI |
| Python | run on 3.5, 3.6, 3.7, 3.8, 3.11, 3.12 and 3.13 |

---

## Phase 1: correctness and trust (DONE)

| # | Item | Outcome | Evidence |
|---|---|---|---|
| 1 | Real captures | `tests/corpus/`: 29 captures from tcpdump 4.99.4's own test suite (BSD, licence included), 2,681 recorded tcpdump answers, checked by `selftest` offline | `tools/corpus.py check`. Whole suite: `tools/corpus.py xcheck` → 0 unexplained differences |
| 2 | Old Pythons | `selftest`, `check_docs`, every CLI and the unit tests pass on 3.5.10, 3.6.15, 3.7.17 and 3.8.20 | docker `python:3.x-slim`; CI job `old-python` |
| 3 | Old libpcap | Measured on 1.5.3 (CentOS 7), 1.7.4, 1.8.1, 1.9.1 (Rocky 8) and 1.10.0 (Rocky 9). 1.9.1 and newer agree fully. Older versions lack `tcp-ece/cwr`, `icmp6[]` and 0x88a8 in `vlan` | `knowledge/bpf/08-libpcap-versions.md`; CI job `libpcap-versions` |
| 4 | Live VLAN | Measured with a veth pair on Linux 6.18, both directions, five libpcap versions. Found that `ether[12:2] = 0x8100` never matches live on receive, and that live `vlan` on libpcap 1.8 and older misses inline tags. Docs corrected | `tests/live/live_vlan.py`; 08 § Live capture |
| 5 | DNS opt-in | Host names are errors unless `--allow-dns` (`compile_filter(..., allow_dns=True)`) | `tests/test_bpf.py` |
| 6 | CI | `.github/workflows/ci.yml` has three jobs. `test`: 3.11/3.13 + tcpdump + pyflakes. `old-python`: 3.5–3.8. `libpcap-versions`: Rocky 8/9 | every job was simulated locally before pushing |
| 7 | Unit tests | 40 `unittest` cases: tokenizer, parser structure, syntax errors, evaluation semantics, link types, I/O edge cases, decoder fuzzing, bpfgen on mangled captures | `python3 -m unittest discover -s tests` |

Bugs Phase 1 found and fixed:
- `ether proto 0x8100` was treated like `vlan`. libpcap compiles a plain
  EtherType compare.
- The pcap link-type field kept FCS flag bits. Link types 12/14 were not read
  as raw IP.
- libpcap rejects a divisor it can fold to zero at compile time; bpfkit
  silently matched nothing.
- `ether proto` and `ip proto` names accepted names that libpcap rejects
  (`\lldp`, `\vlan`, `\icmp6`, ...).
- Decoder crashes on truncated or malformed packets: half-set address
  fields, and `l3`/`l4` set before their fields existed. `profile` and
  `suggest` crashed on those packets too.
- Docs:
  - `ether[12:2] = 0x8100` was recommended as a VLAN test, but it fails live.
  - "Newer libpcap" claims were vague; they now name exact versions.
  - Gotcha 13 contradicted measured `ip broadcast` behaviour.

What Phase 1 did not cover:
- **No real OT-protocol captures** (Modbus/DNP3/S7) in the committed corpus.
  No clearly licensed ones were found, so Modbus is covered only
  synthetically (`samples/demo.pcap`).
- **No physical NIC or SPAN port tested.** The live VLAN results come from
  veth on one kernel; physical NICs with VLAN offload and SPAN ports were not
  tested.
- **No CI gate for libpcap 1.5.3–1.8.1.** Their differences are documented
  rather than checked in CI.
- **First CI run on GitHub: 6 of 8 jobs passed.** Both `libpcap-versions`
  jobs failed because the container's tcpdump wrote root-owned 0600 files that
  the runner user could not read. Fixed by running it with the runner's uid
  (reproduced and verified as uid 1001 locally).

New items Phase 1 suggested (added below):
- An optional `--libpcap 1.5` compatibility mode for filters that will run on
  old sensors.
- A warning in `bpfgen` when a generated filter uses a feature that needs a
  newer libpcap.

## Phase 2: things that should be better

### Filter engine (`bpfkit/bpf.py`)

- **Missing primitives:** `mpls`, `pppoes`, `geneve`, `protochain`,
  `gateway`, 802.11 (`wlan`, `type/subtype`, radiotap link types), `llc`,
  `ifname`/pflog. These are rejected today; MPLS and PPPoE matter on some OT
  WANs.
- **No bytecode output.** We interpret instead of compiling, so
  `iptables -m bpf` / `SO_ATTACH_FILTER` users still need tcpdump somewhere.
  A small cBPF code generator (the same AST to `-dd`/`-ddd`) would remove
  that dependency. Verify it by diffing its output's behaviour against
  `tcpdump -d` programs.
- **Optimiser difference (gotcha 6).** We match libpcap's *unoptimised*
  semantics on out-of-range loads. Either emulate the optimiser's
  "already-decided" short-circuit or warn when a filter mixes payload loads
  with `or`.
- **Performance.** It is a closure-based interpreter, about 0.4 s per 60k
  packets for simple filters. Fine for analysis, slow for multi-GB files. Two
  options: compile the AST to Python source once per filter, or add a
  `--prefilter` fast path for plain host/port filters.

- **libpcap version targeting.** Add `--libpcap 1.5|1.8|1.9` to `capread`
  and `bpfgen`, emulating the measured differences in
  `knowledge/bpf/08-libpcap-versions.md`: `vlan` without 0x88a8, no
  `tcp-ece/cwr`, no `icmp6[]`. Filters for a RHEL 7 sensor can then be
  tested here.

### Pattern mining (`bpfkit/bpfgen.py`)

- **Target-version warnings.** Warn when a suggested filter uses something an
  older sensor libpcap lacks, or a VLAN form that behaves differently live
  (see 08).

- **Greedy learner.** Sequential covering with FOIL gain can miss shorter
  filters. Add a small beam search (width 3–5), and a final step that tries
  merging rules, e.g. `port 21 or port 22` into `portrange 21-22`, or `host A
  or host B` into a `net`.
- **Overfitting with one example.** With a single target, any unique field
  wins. The variability penalty helps (counters lose to function codes), but
  `suggest` should:
  - say plainly "1 example: add more or use `--where`";
  - offer `--negatives` (explicit "must not match" packets) rather than
    "everything else".
- **Payload features stop at byte 15**, plus u16/u32 words at 0 and 4.
  - Make the depth configurable (`--payload-bytes N`).
  - Mine aligned constants at any offset shared by all targets, not only
    per-byte features.
  - Use the existing `needle_features` approach for discovered constants too.
- **Features are missing for:**
  - IPv6 TCP flags (`ip6[53]`);
  - DSCP/ECN;
  - ICMP code;
  - TCP options presence;
  - IP options;
  - port ranges (ephemeral client range);
  - MAC OUI;
  - DNS opcode/RCODE;
  - time windows (BPF can't, but we could report that targets are clustered
    in time).
- **VLAN edge cases.** A rule cannot mix terms from two VLAN depths, and
  VLAN-id features are approximate for frames with more tags than the rule's
  depth. Verification catches the results but the learner may choose badly.
  Model per-depth rules explicitly.
- **Memory.** `Capture` keeps every packet and decoded dict in memory, so
  analysis is capped at `--max-packets` (default 200k). Stream features into
  bitsets without keeping payloads, or sample uniformly with a reported
  sampling rate.
- **`profile` BPFs are templates and are not verified.** Run each through the
  engine and print the measured count next to it, at least for captures
  under 100k packets.
- **Explanations.** Group the output by intent ("who", "what service", "what
  message") and say why a general filter is broader, using examples of the
  extra packets.

### Reader and decoder (`bpfkit/capread.py`, `bpfkit/decode.py`, `bpfkit/pcapio.py`)

- Time filters (`--start/--end`), multiple input files, stdin (`-r -`).
- `-w` to pcapng, and keeping per-interface link types when the input mixes
  them. Today `-w` fails on mixed link types.
- Timestamps in pcapng Simple Packet Blocks are 0. Show them as unknown
  instead.
- More application hints: DNP3 function codes, S7 ROSCTR, IEC-104 frame
  type, EtherNet/IP commands, SMB, Kerberos, LDAP, SNMP community (masked).
- TCP stream view (`--follow N`) for context. It is analysis only; BPF still
  cannot do it.
- 802.11/radiotap decoding (read-only) so Wi-Fi captures at least list
  sensibly.

### Skills (`.claude/skills/`)

- **No trigger/behaviour evals yet.** Write eval prompts ("read this .cap",
  "make a filter for the scan", "why doesn't my vlan filter work") and
  measure triggering and quality with the skill-creator workflow.
- **Repo-root paths.** Both skills call `tools/*.py` relative to the
  repository root. Make them robust when the skill is copied to
  `~/.claude/skills`, e.g. via an environment variable or a bundled copy of
  `bpfkit` inside each skill.
- Add a third, small `bpf-explain` flow: paste a filter, get a plain-English
  explanation plus the gotchas that apply, with `--check` output.

### Knowledge base (`knowledge/bpf/`)

- Add a "BPF for common OT sensor deployments" page: SPAN/TAP placement,
  allow-list capture filters, and the noise filters to start with.
- Add "translating Wireshark display filters to BPF", the most common user
  confusion.
- Record the libpcap version for every recipe that needs a newer libpcap
  (after Phase 1 item 3).

### Repository hygiene

- Commits are currently authored as "Claude". Set the owner's identity for
  future commits.
- Add `LICENSE` and a `CHANGELOG.md`.
- Add a `Makefile`-free `tools/release.py` that builds the air-gap bundle
  (`git bundle` + `sha256sum`) and runs `selftest` first.

## Phase 3: nice to have

- A cBPF disassembler/emulator so users can paste `tcpdump -dd` bytecode from
  a sensor and test it against captures offline.
- eBPF/XDP export notes, e.g. generate a C snippet for `tc`/XDP from a learnt
  rule.
- An HTML report from `profile` and `suggest` for sharing inside the enclave
  (static file, no JavaScript dependencies).

## Definition of done for any change

1. `python3 tools/selftest.py` prints `RESULT: PASS`. Run it with tcpdump
   installed when possible, so the live cross-check runs too.
2. `python3 tools/check_docs.py` reports 0 problems when the knowledge base
   changed.
3. `python3 -m pyflakes bpfkit tools` is clean.
4. No new dependencies, and Python 3.5+ syntax only.
