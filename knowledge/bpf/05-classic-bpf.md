# Classic BPF (cBPF): what a filter compiles to

libpcap compiles a filter expression into a small program for the BSD Packet
Filter virtual machine. The kernel, or libpcap itself when reading files, runs
that program on every packet. A return value of 0 drops the packet; any other
value is the number of bytes to keep.

## The machine

| Part | Description |
|---|---|
| `A` | 32-bit accumulator |
| `X` | 32-bit index register |
| `M[0..15]` | scratch memory |
| input | the packet bytes, starting at the link-layer header (or at the IP header for `-y RAW` / `DLT_RAW`) |
| program | at most 4096 instructions; jumps go forward only, so there are **no loops** and it always terminates |

Each instruction is 8 bytes: `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`.

| Class | Mnemonics | Meaning |
|---|---|---|
| load | `ld` / `ldh` / `ldb` `[k]`, `[x + k]` | load a 4/2/1-byte big-endian word into A (an out-of-range load returns 0 = drop) |
| | `ld #len` | wire length |
| | `ldxb 4*([k]&0xf)` | X = IPv4 header length |
| store | `st M[i]`, `stx M[i]` | |
| ALU | `add sub mul div mod and or xor lsh rsh neg` with `#k` or `x` | |
| jump | `jeq jgt jge jset #k  jt N jf M`, `ja N` | |
| return | `ret #k` (keep k bytes; 0 = drop), `ret a` | |
| misc | `tax`, `txa` | |

## Reading `tcpdump -d`

```
$ tcpdump -d 'ip and tcp dst port 22'          # Ethernet
(000) ldh      [12]                       ; EtherType
(001) jeq      #0x800           jt 2  jf 10 ; IPv4?
(002) ldb      [23]                       ; 14 + 9 = IP protocol
(003) jeq      #0x6             jt 4  jf 10 ; TCP?
(004) ldh      [20]                       ; 14 + 6 = flags/fragment offset
(005) jset     #0x1fff          jt 10 jf 6  ; non-first fragment -> drop
(006) ldxb     4*([14]&0xf)               ; X = IP header length
(007) ldh      [x + 16]                   ; 14 + 2 = TCP destination port
(008) jeq      #0x16            jt 9  jf 10 ; == 22 ?
(009) ret      #262144                    ; accept (snaplen bytes)
(010) ret      #0                         ; drop
```

How `vlan 20 and ip` compiles. Notice the fixed +4 shift (`[16]`), which is
why the order of `vlan` matters:

```
(000) ldh [12]   (001) jeq #0x8100 jt 4 jf 2   (002) jeq #0x88a8 jt 4 jf 3   (003) jeq #0x9100 jt 4 jf 10
(004) ldh [14]   (005) and #0xfff   (006) jeq #0x14 jt 7 jf 10
(007) ldh [16]   (008) jeq #0x800 jt 9 jf 10     (009) ret #262144   (010) ret #0
```

## Output formats

| Command | Output | Used by |
|---|---|---|
| `tcpdump -d` | assembly listing | humans |
| `tcpdump -dd` | C initialiser `{ 0x28, 0, 0, 0x0000000c },` | `struct sock_filter[]` in C |
| `tcpdump -ddd` | decimal: first line = count, then `code jt jf k` | `iptables -m bpf`, `tc`, scripts |
| `-y RAW` | compile for packets that start at the IP header | iptables `xt_bpf`, raw/tun sockets |
| `-y EN10MB`, `-y LINUX_SLL` | compile for that link type | |

`tcpdump -dd 'ip and tcp dst port 22'`:

```c
struct sock_filter code[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 8, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 6, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000016 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
};
```

`tcpdump -ddd -y RAW 'tcp dst port 22' | paste -sd, -` gives the format
iptables expects (IPv4 and IPv6, starting at the IP header):

```
19,48 0 0 0,84 0 0 240,21 0 4 96,48 0 0 6,21 0 13 6,40 0 0 42,21 10 11 22,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 2,21 0 1 22,6 0 0 262144,6 0 0 0
```

## Attaching bytecode yourself (Linux)

**C** uses `SO_ATTACH_FILTER` on a packet socket:

```c
struct sock_fprog prog = { .len = sizeof(code)/sizeof(code[0]), .filter = code };
int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
```

**Python** (stdlib only; needs root or CAP_NET_RAW). Tested on Linux x86-64:
only TCP to port 22 gets through.

```python
import ctypes, socket, struct
code = [(0x28,0,0,12),(0x15,0,8,0x800),(0x30,0,0,23),(0x15,0,6,6),(0x28,0,0,20),
        (0x45,4,0,0x1fff),(0xb1,0,0,14),(0x48,0,0,16),(0x15,0,1,22),(0x6,0,0,0x40000),(0x6,0,0,0)]
buf = ctypes.create_string_buffer(b"".join(struct.pack("HBBI", *c) for c in code))
fprog = struct.pack("HL", len(code), ctypes.addressof(buf))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))   # ETH_P_ALL
s.setsockopt(socket.SOL_SOCKET, 26, fprog)                              # 26 = SO_ATTACH_FILTER
```

Other ways to load bytecode:

- **iptables:** `iptables -A INPUT -m bpf --bytecode "<count>,<code jt jf k>,..." -j ...`.
  Packets start at the IP header, so compile with `-y RAW`.
- **tc:** `tc filter ... bpf bytecode "<same format>"` (cls_bpf). Check where
  the packet data starts at your hook before you pick the `-y` link type.
- **BSD:** `/dev/bpf` with `ioctl(BIOCSETF)`.

## Without tcpdump on the air-gapped host

bpfkit does not emit bytecode; it interprets the expression directly. When
you need bytecode on a host without tcpdump:

- compile it with `tcpdump -dd`/`-ddd` on any Linux box (no network needed),
  using the same `-y` link type, and carry the text across; or
- write it by hand from the listings above. Remember the 4096-instruction
  limit, forward-only jumps, and that out-of-range loads drop the packet.

## cBPF vs eBPF

- **eBPF** is the modern in-kernel VM: 64-bit registers, maps, helpers, and
  verified bounded loops. It is used by XDP, tc-bpf, tracing, seccomp-bpf
  (which is cBPF over syscalls) and so on.
- **Capture filters are cBPF.** Linux translates them to eBPF internally.
  Tools like `bpftrace` and `bpftool` are about eBPF programs, not
  tcpdump-style filters.
