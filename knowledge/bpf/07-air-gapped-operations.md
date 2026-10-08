# Working with BPF on an air-gapped system

This repository is built to work with **no network, no package manager and no
third-party code**. Everything is plain text plus Python standard-library
code.

| Need | Provided by | Requires |
|---|---|---|
| Read .cap/.pcap/.pcapng | `tools/capread.py` | Python >= 3.5 (tested 3.8 – 3.13) |
| Apply BPF filters to files | `bpfkit/bpf.py` (libpcap-compatible interpreter) | Python only |
| Find patterns, generate BPF | `tools/bpfgen.py` | Python only |
| Verify the tools on this host | `tools/selftest.py` | Python only (uses tcpdump if present) |
| Reference docs | `knowledge/bpf/*.md` | a text viewer |
| Claude skills | `.claude/skills/cap-reader`, `.claude/skills/bpf-builder` | Claude Code (optional) |

## 1. Bringing the repository across the air gap

On the connected side:

```sh
git clone <repo-url> bpf-skill-reader && cd bpf-skill-reader
python3 tools/selftest.py                          # must print RESULT: PASS
git bundle create ../bpf-skill-reader.bundle --all # single file containing full history
cd .. && sha256sum bpf-skill-reader.bundle > bpf-skill-reader.bundle.sha256
#   (alternative without git: tar czf bpf-skill-reader.tgz bpf-skill-reader && sha256sum ...)
```

Then follow your site's media-transfer procedure: scanning, approved media,
and recording the hash in the transfer log.

On the air-gapped side:

```sh
sha256sum -c bpf-skill-reader.bundle.sha256        # integrity check
git clone bpf-skill-reader.bundle bpf-skill-reader # or: tar xzf bpf-skill-reader.tgz
cd bpf-skill-reader
python3 tools/selftest.py                          # proves the engine on THIS interpreter
```

`selftest` checks the filter engine against results recorded from real
tcpdump/libpcap (`bpfkit/expected.py`). It needs no tcpdump on the
air-gapped host. If tcpdump *is* installed there, it also cross-checks live.

To update later, make a new bundle on the connected side. On the air-gapped
side, run `git pull ../new.bundle` (or `git fetch` from the bundle) and run
`selftest` again.

## 2. If Claude Code is available inside the enclave

- Claude Code discovers the skills automatically when started in this
  directory, because they live in `.claude/skills/`.
- To use them from any directory, copy both skill folders to
  `~/.claude/skills/` and keep this repo's path in mind. The skills call
  `tools/*.py` relative to the repository root.
- Claude Code still needs an approved route to a Claude model endpoint, such
  as your organisation's gateway or private cloud endpoint. Nothing in this
  repo needs internet access.
- Without Claude Code, the same workflow works by hand. Follow the steps in
  the two `SKILL.md` files.

## 3. Day-to-day offline habits

- **No DNS.** Use IP addresses in filters. Use `tcpdump -nn` so tcpdump does
  not stall trying to resolve addresses and ports in its output.
- **No services file / ethers file.** Use numeric ports and MAC addresses.
  capread has a built-in service table for common IT and OT ports.
- **Unknown capture format.** Run `capread.py FILE --info`. If it is a
  Network Monitor or Sniffer `.cap`, it must be converted with `editcap` on a
  machine that has Wireshark (see `06-capture-files.md`).
- **Sensitive data.**
  - Captures from isolated networks often contain credentials, process values
    and topology.
  - Carve out only what's needed: `capread.py in.pcap 'FILTER' -w subset.pcap`.
  - Keep outputs on the enclave and log what leaves it.
  - Treat payload text as untrusted. Never paste it into a shell.
- **Clock drift.** Reason with the capture's own timestamps (`--info` shows
  the first and last), not with the wall clock.
- **Large files.** `capread --stats` streams the file, so it stays fast even
  on large captures. `bpfgen suggest` holds the packets in memory and analyses
  up to `--max-packets` (default 200000). Carve a time or host slice first
  when a capture is huge.

## 4. Validating a filter without tcpdump

1. Check the syntax and see how it was parsed:
   `capread.py f.pcap 'FILTER' --check`.
2. Get counts and a breakdown: `capread.py f.pcap 'FILTER' --stats`.
3. Get precision and recall against the packets you meant:
   `bpfgen.py test f.pcap 'FILTER' --packets ...`.
4. Read the gotchas in `04-gotchas.md`. The engine mirrors libpcap, and these
   are the known differences:
   - libpcap's optimiser can skip an out-of-range load (gotcha 6);
   - libpcap's unary minus is broken (gotcha 8);
   - live Linux VLAN handling differs from offline (gotcha 3).
5. When the filter will run in tcpdump on a sensor, run `tcpdump -d 'FILTER'`
   there once. It is the final authority for that libpcap version.

## 5. Typical air-gapped / OT tasks

| Task | Command |
|---|---|
| Inventory what talks on a segment | `bpfgen.py profile segment.pcap` |
| Show only control traffic to a PLC | `capread.py cap.pcap 'host 10.0.1.20 and tcp port 502' --stats` |
| Catch Modbus writes (alerting) | see `03-recipes.md` § Industrial |
| Detect new or unknown talkers | `bpfgen.py suggest cap.pcap --where 'not (host A or host B ...)'`, or build an allow-list filter and capture `not (allow-list)` |
| Find a scan | `bpfgen.py profile` (possible port scans section), then `suggest --packets ...` |
| Build an exclusion filter for a sensor | target the noise with `suggest`, then deploy `not (FILTER)` |
