# libpcap versions and live-capture differences (measured)

Air-gapped hosts often run old distributions, and the libpcap there decides
what a filter means on the sensor. Everything below was **measured**, not
taken from changelogs, using the distribution packages:

| Distribution | tcpdump | libpcap |
|---|---|---|
| CentOS 7 / RHEL 7 | 4.9.2 | **1.5.3** |
| Ubuntu 16.04 | 4.9.3 | 1.7.4 |
| Ubuntu 18.04 | 4.9.3 | 1.8.1 |
| Rocky 8 / RHEL 8 (Ubuntu 20.04 has the same libpcap) | 4.9.3 | 1.9.1 |
| Rocky 9 / RHEL 9 | 4.99.0 | 1.10.0 |
| Ubuntu 24.04 | 4.99.4 | 1.10.4 |

Method:
- Run `tools/check_docs.py --tcpdump "docker exec <box> tcpdump"` over all 115
  recipes.
- Run `tools/corpus.py xcheck tests/corpus samples/demo.pcap --tcpdump ...`
  (2,827 filter × capture comparisons per version).
- Run `tests/live/live_vlan.py` for live capture.

## Offline filtering (reading a file)

**libpcap 1.9.1 and newer agree with bpfkit on every comparison.**

On older versions, these differences show up:

| Feature | 1.5.3 | 1.7.4 | 1.8.1 | 1.9.1+ | Portable alternative |
|---|---|---|---|---|---|
| `tcp-ece`, `tcp-cwr` constants | error | error | error | ok | `tcp[13] & 0x40`, `tcp[13] & 0x80` |
| `icmp6[...]`, `icmp6type`, `icmp6code`, `icmp6-*` names | error | error | error | ok | `ip6[6] = 58 and ip6[40] = N` |
| `vlan` matches 802.1ad TPID 0x88a8 (QinQ outer tag) | no | no | yes | yes | `ether[12:2] = 0x88a8` (offline only, see below) |
| `geneve` | error | ok | ok | ok | - |

- Every one of the 115 recipes works on 1.5.3 except the ECE/CWR one, which
  needs 1.9 or newer.
- These are the same on all versions from 1.5.3 to 1.10.4:
  - the unary-minus bug (gotcha 8);
  - the optimiser out-of-range difference (gotcha 6);
  - divide-by-zero being a compile error;
  - `ip broadcast` reading;
  - the accepted `ether proto \name` and `ip proto \name` names.

bpfkit implements the modern (1.9+) behaviour. When a filter must run on an
older sensor, avoid the features in the table, then check once with
`tcpdump -d 'FILTER'` on that sensor.

## Live capture on Linux and VLANs

When Linux **receives** a tagged frame, the kernel removes the 802.1Q tag
before any capture filter runs and keeps it as metadata. libpcap puts the tag
back into the packet it hands you, so **saved files contain the tag**, but the
filter itself never saw it. When Linux **sends** a frame whose tag is part of
the data (as here), the tag is still inline when the filter runs.

The table below comes from `tests/live/live_vlan.py` on Linux 6.18 with a
veth pair. It sends 3 frames tagged VLAN 20 (UDP port 514) and 3 untagged
frames (UDP port 515). Each cell shows the number of packets captured live,
then the result of the same filter applied to the saved file. bpfkit always
equals the offline column.

| Filter | Receive, all versions | Send, libpcap 1.9.1+ | Send, libpcap 1.5.3 / 1.8.1 |
|---|---|---|---|
| `ip` | **6** / 3 | 3 / 3 | 3 / 3 |
| `udp port 514` | **3** / 0 | 0 / 0 | 0 / 0 |
| `vlan` | 3 / 3 | 3 / 3 | **0** / 3 |
| `vlan 20 and ip` | 3 / 3 | 3 / 3 | **0** / 3 |
| `not vlan` | 3 / 3 | 3 / 3 | **6** / 3 |
| `ip or (vlan and ip)` | 6 / 6 | 6 / 6 | **3** / 6 |
| `(vlan and ip) or ip` | 3 / 3 (1.9.1+); **6** / 3 (1.5.3, 1.8.1) | 3 / 3 | 3 / 3 |
| `ether[12:2] = 0x8100` | **0** / 3 | 3 / 3 | 3 / 3 |

What this means in practice:

1. **On the receive path, untagged-style filters also catch tagged traffic
   live.** `ip`, `host`, `port` and the like match tagged frames, because the
   kernel stripped the tag. The same filter on the saved file does not.
2. **Never use `ether[12:2] = 0x8100` (or `0x88a8`) live.** On the receive
   path the filter never sees the tag. It is fine for offline files.
3. **Use the `vlan` keyword for live VLAN filters.** It reads the kernel
   metadata on receive. On libpcap 1.9 and newer it also checks inline tags,
   so it gives the same answer live and offline in both directions.
4. **On libpcap 1.8 and older (RHEL 7, Ubuntu 18.04) live `vlan` only reads
   the metadata.** Frames that still carry an inline tag are invisible to it.
   That means traffic sent by a host that builds tags in software, and
   possibly traffic on tagged mirror (SPAN) ports, depending on the NIC and
   driver. Test on the real sensor with known traffic before relying on it.
5. **`ip or (vlan and ip)` is the safest "tagged or not" form.** It is
   correct offline, live on receive, and live on send with libpcap 1.9 and
   newer.

```bpf
ip or (vlan and ip)
udp port 514 or (vlan and udp port 514)
vlan 20 and host 10.20.0.5
```

To reproduce: create the veth pair as shown in `tests/live/live_vlan.py`,
then run it for `vtest1` (receive) and `vtest0` (send). Pass
`--tool LABEL="tcpdump command"` for each extra libpcap build.
