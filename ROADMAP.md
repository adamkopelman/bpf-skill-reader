# Roadmap: plan and known weaknesses

This is an honest list of what works today, what is weak, and what to do
next, in priority order. Each item names the files involved and how to know
it is done.

## Where things stand (v1.0.0)

| Area | State |
|---|---|
| Capture reading | pcap (µs/ns/modified), pcapng, snoop, gzip. Ethernet, raw IP, SLL/SLL2, NULL/LOOP |
| Filter engine | libpcap-compatible interpreter. 182 test cases + 115 doc recipes agree with tcpdump 4.99.4 / libpcap 1.10.4 |
| Pattern mining | `bpfgen profile/suggest/test`. Greedy rule learner with tcpdump-verified output |
| Knowledge base | 7 offline reference files. Every recipe filter is machine-checked |
| Verification | `tools/selftest.py` (works without tcpdump) and `tools/check_docs.py` |
| Python | static analysis says 3.5+; actually run on 3.8, 3.11, 3.12 and 3.13 |

---

## Phase 1: correctness and trust (do first)

1. **Test on real captures, not only synthetic ones.**
   - **Problem.** `bpfkit/expected.py` comes from one synthetic 69-packet
     capture. Real traffic has TCP/IP options, IPv6 extension headers,
     truncated packets (snaplen), odd link types and malformed frames.
   - **Plan.** Build a small corpus under `samples/` from public, licensable
     captures and a few OT-protocol captures. Add a script that records
     tcpdump results for `filters × captures` into `expected.py`.
   - **Done when.** `selftest` covers at least 5 real captures, with 0
     mismatches.
2. **Test the oldest Pythons we claim.**
   - **Problem.** We claim 3.5+ but have only run 3.8 and newer. Air-gapped
     RHEL 7/8 hosts ship 3.6.
   - **Done when.** `selftest` passes on 3.6 and 3.7, either in a container or
     on a real enclave host.
3. **Test against older libpcap.**
   - **Problem.** The knowledge base and `expected.py` were verified on
     libpcap 1.10.4 only. RHEL 7 ships 1.5.3, and the `icmp6[...]` support
     and VLAN code paths differ.
   - **Plan.** Re-run `check_docs.py` and `selftest` with older tcpdump
     builds, and record which recipes need a newer libpcap.
4. **Verify live-capture VLAN behaviour.**
   - **Problem.** `knowledge/bpf/04-gotchas.md` §3 describes Linux
     tag-stripping from libpcap source knowledge. It was not checked on a
     live tagged interface.
   - **Done when.** It has been checked on a live tagged interface, and the
     doc gives exact libpcap/kernel versions.
5. **Make hostname resolution opt-in.**
   - **Problem.** `bpf._resolve_host` calls `getaddrinfo`. On an air-gapped
     host that can hang until the resolver times out, or leak a DNS query to
     an internal resolver.
   - **Plan.** Off by default (error: "use an IP address"), with an
     `--allow-dns` flag.
6. **Add CI.**
   - **Plan.** A GitHub Actions workflow that installs tcpdump, then runs
     `selftest`, `check_docs` and `pyflakes` on Python 3.6 (container),
     3.8 and 3.13.
7. **Add unit tests for the parser.**
   - **Problem.** The current tests are end-to-end only.
   - **Plan.** Add `unittest` cases (stdlib) for the tokenizer edge cases:
     MAC vs IPv6 vs `tcp[13:1]`, `portrange`, octal, `len-14`, `\tcp`
     escapes. Add round-trip cases for error messages.

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

### Pattern mining (`bpfkit/bpfgen.py`)

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
