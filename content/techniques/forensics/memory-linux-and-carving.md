---
title: "Memory Forensics - Linux Images and Raw Memory Carving"
category: forensics
subcategory: memory
type: technique
tags: [linux-memory, volatility3, volatility, lime, avml, dwarf2json, isf, symbol-table, bash-history, strings, binwalk, foremost, photorec, bulk-extractor, carving, task-struct, memory-dump, dfir]
difficulty: hard
summary: "Volatility 3 on Linux dumps, building an ISF with dwarf2json, and what to do when no profile exists: treat RAM as a blob and carve."
when_to_use:
  - "The dump is .lime / .core / AVML output, or windows.info fails but banners.Banners shows a Linux banner"
  - "No symbol table exists for the target kernel and you cannot build one"
  - "You only need one artifact (bash history, an SSH key, a file) and full parsing is overkill"
  - "The image is a container, an embedded device, or a partial dump"
tools: [volatility3, volatility, dwarf2json, lime, avml, binwalk, foremost, photorec, bulk-extractor, strings]
related: [memory-volatility3-workflow, memory-volatility2, disk-file-carving, memory-credential-extraction]
---

## TL;DR

Linux memory analysis needs a symbol table that matches the **exact** kernel build. If you have it,
`linux.bash.Bash`, `linux.pslist`, `linux.psaux`, `linux.sockstat` and `linux.proc.Maps` do the job.
If you do not, stop fighting the framework: `strings`, `grep`, `binwalk` and targeted struct
scanning recover most CTF flags from a raw dump in minutes.

## Recognise it

- `file mem.lime` -> `data`; the first 32 bytes start with `EMiL` (LiME header magic `0x4C694D45`).
- AVML output starts with `AVML` and is a compressed multi-range container.
- `strings -a mem.raw | grep -m1 'Linux version'` prints a kernel banner.
- `windows.info` fails with "unsatisfied requirement" but the dump is clearly an OS image.

## Acquisition formats

```sh
# LiME kernel module capture (format=lime writes a header per memory range)
insmod lime.ko "path=/tmp/mem.lime format=lime"
# raw format has no headers and is directly greppable but has physical holes as zeros
insmod lime.ko "path=/tmp/mem.raw format=raw"
# padded format fills the holes so offsets equal physical addresses
insmod lime.ko "path=/tmp/mem.padded format=padded"
# AVML: static binary, no kernel module needed, works on most cloud kernels
./avml output.lime
# convert an AVML/compressed capture to raw
./avml-convert --format raw input.lime output.raw
# a /proc/kcore snapshot when nothing else is available (live only)
dd if=/proc/kcore of=kcore.dd bs=1M count=2048
# identify the LiME header ranges by hand
xxd -l 32 mem.lime
```

LiME header layout (little-endian): magic `0x4C694D45` (u32), version (u32), s_addr (u64),
e_addr (u64), reserved (u64) = 32 bytes, then the range's bytes, then the next header.

## Volatility 3 on Linux

```sh
# does a symbol table match? this prints every kernel banner found in the dump
vol3 -f mem.lime banners.Banners
# process list from the task_struct linked list
vol3 -f mem.lime linux.pslist.PsList
# with the full argv, like ps aux
vol3 -f mem.lime linux.psaux.PsAux
# parent/child tree
vol3 -f mem.lime linux.pstree.PsTree
# the flag-bearing plugin: recovered bash history, per process, with timestamps
vol3 -f mem.lime linux.bash.Bash
# open file descriptors per process
vol3 -f mem.lime linux.lsof.Lsof
# memory mappings of one process (equivalent of /proc/PID/maps)
vol3 -f mem.lime linux.proc.Maps --pid 1337
# dump a process' mapped regions to disk
vol3 -f mem.lime -o ./out linux.proc.Maps --pid 1337 --dump
# ELF images resident in memory
vol3 -f mem.lime linux.elfs.Elfs
# injected/anomalous executable mappings
vol3 -f mem.lime linux.malfind.Malfind
# sockets with state, like ss -antp
vol3 -f mem.lime linux.sockstat.Sockstat
# environment variables per process
vol3 -f mem.lime linux.envars.Envars
# mounted filesystems
vol3 -f mem.lime linux.mountinfo.MountInfo
# kernel ring buffer (dmesg)
vol3 -f mem.lime linux.kmsg.Kmsg
# loaded kernel modules, and the list-vs-scan rootkit check
vol3 -f mem.lime linux.lsmod.Lsmod
vol3 -f mem.lime linux.check_modules.Check_modules
# syscall table entries pointing outside the kernel text
vol3 -f mem.lime linux.check_syscall.Check_syscall
# tty hooks (keylogger detection)
vol3 -f mem.lime linux.tty_check.tty_check
# shared libraries loaded per process
vol3 -f mem.lime linux.library_list.LibraryList
# capabilities and credentials per task
vol3 -f mem.lime linux.capabilities.Capabilities
# macOS equivalents when the dump is a Mac
vol3 -f mem.raw mac.pslist.PsList
vol3 -f mem.raw mac.netstat.Netstat
vol3 -f mem.raw mac.bash.Bash
```

## Building an ISF symbol table

```sh
# 1) get the kernel with debug symbols for the EXACT build the dump came from
uname -a                                   # on the source box, if you have it
strings -a mem.lime | grep -m1 'Linux version'   # otherwise read it from the dump
apt-get install -y linux-image-$(uname -r)-dbgsym   # needs the ddebs repo
# 2) build dwarf2json (Go)
git clone https://github.com/volatilityfoundation/dwarf2json && cd dwarf2json && go build
# 3) produce the ISF JSON from vmlinux (+ System.map for symbol addresses)
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-6.1.0-18-amd64 \
                   --system-map /boot/System.map-6.1.0-18-amd64 > linux-6.1.0-18.json
# 4) compress and drop it where volatility3 looks
xz -9 linux-6.1.0-18.json
mkdir -p /opt/volatility3/volatility3/symbols/linux
cp linux-6.1.0-18.json.xz /opt/volatility3/volatility3/symbols/linux/
# 5) confirm it is picked up
vol3 -f mem.lime linux.pslist.PsList
# force a symbol directory explicitly if auto-discovery fails
vol3 --symbol-dirs /opt/symbols -f mem.lime linux.pslist.PsList
```

If you cannot get `dbgsym`, you can sometimes build from the distro's kernel source with
`CONFIG_DEBUG_INFO=y`, but the config must match bit for bit. In a CTF, the challenge author
usually ships the ISF or the vol2 profile zip alongside the dump - look for a `.json.xz` or `.zip`.

## No profile, no symbols: treat it as a blob

This is the pragmatic CTF path and it works on any OS, any architecture, truncated dumps included.

```sh
# 1) the flag grep, both encodings, with byte offsets so you can seek back
strings -a -t d mem.raw | grep -aoiE '[a-z0-9_]{2,16}\{[^}]{4,120}\}' | sort -u
strings -a -t d -el mem.raw | grep -aoiE '[a-z0-9_]{2,16}\{[^}]{4,120}\}' | sort -u
# 2) shell history fragments: look for the surrounding context, not the file
strings -a mem.raw | grep -aE '^(sudo|ssh|scp|curl|wget|nc |python3?|export |cat /etc)' | sort -u
strings -a mem.raw | grep -aB2 -A8 'HISTFILE'
# 3) credentials and keys
strings -a mem.raw | grep -aoE '^\S+:\$[0-9a-z]\$[^:]{10,}:' | sort -u   # shadow lines
strings -a mem.raw | grep -a -A30 'BEGIN OPENSSH PRIVATE KEY'
strings -a mem.raw | grep -aoE 'ssh-(rsa|ed25519) [A-Za-z0-9+/=]{40,}'
strings -a mem.raw | grep -aoE '(AKIA|ASIA)[A-Z0-9]{16}'
# 4) environment variables (they sit contiguously, NUL-separated, in each task's stack)
strings -a mem.raw | grep -aE '^[A-Z_]{3,30}=' | sort -u | head -60
# 5) embedded files
binwalk mem.raw                    # list signatures
binwalk -e --dd='.*' mem.raw       # extract everything it recognises
foremost -t all -i mem.raw -o fore_out
photorec /d pr_out /cmd mem.raw search
bulk_extractor -o be_out mem.raw
# 6) the specific formats that show up most in CTF memory dumps
grep -aob 'PK\x03\x04' mem.raw | head          # zip/docx/apk
grep -aob '\x89PNG' mem.raw | head             # png
grep -aob '\xff\xd8\xff' mem.raw | head        # jpeg
grep -aob '%PDF-' mem.raw | head               # pdf
grep -aob 'SQLite format 3' mem.raw | head     # sqlite
# 7) manual carve from an offset that grep gave you
dd if=mem.raw bs=1 skip=1234567 count=2000000 of=carved.zip status=none
file carved.zip && unzip -l carved.zip
```

## Struct carving without symbols

On x86-64 Linux, `task_struct` contains `char comm[16]`: a NUL-padded process name. Those names
appear in memory in dense clusters because task structs are slab-allocated together. Scanning for
short, printable, NUL-terminated 16-byte runs that look like program names gives you a process
list with no symbol table at all - and the neighbouring bytes are pointers you can follow.

Similar no-symbol tricks:

- `/etc/shadow` lines: `^[a-z_][a-z0-9_-]*:\$[1256y]\$` - carve the surrounding 4 KB page.
- `utmp` records: fixed 384-byte structs with a small `ut_type` enum at offset 0.
- `struct inode`-adjacent path strings: search for `/home/`, `/root/`, `/var/log/`.
- OpenSSH session keys: search for the constant `chacha20-poly1305@openssh.com` and inspect nearby
  heap memory.
- Page-aligned ELF headers: `\x7fELF` at an offset that is a multiple of 0x1000 is a loaded image.

## Code

```python
#!/usr/bin/env python3
"""String extraction from a raw memory image with offsets, ASCII + UTF-16LE + UTF-16BE.

Like `strings -a -t d` but it understands wide strings and takes a regex filter.

    python3 memstrings.py mem.raw --min 8 --grep 'flag\\{'
    python3 memstrings.py mem.raw --min 6 --encodings ascii,utf16le
"""
from __future__ import annotations

import argparse
import re
import sys

CHUNK = 16 * 1024 * 1024
OVERLAP = 8192


def iter_chunks(path: str):
    with open(path, "rb") as fh:
        base, tail = 0, b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                return
            yield base - len(tail), tail + chunk
            base += len(chunk)
            tail = chunk[-OVERLAP:] if len(chunk) >= OVERLAP else chunk


def build_patterns(min_len: int, encodings: set[str]) -> list[tuple[str, re.Pattern[bytes], int]]:
    """(label, pattern, stride) - stride is bytes per character for offset math."""
    pats: list[tuple[str, re.Pattern[bytes], int]] = []
    if "ascii" in encodings:
        pats.append(("ascii", re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len), 1))
    if "utf16le" in encodings:
        pats.append(("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len), 2))
    if "utf16be" in encodings:
        pats.append(("utf16be", re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % min_len), 2))
    return pats


def decode(label: str, raw: bytes) -> str:
    if label == "utf16le":
        return raw.decode("utf-16-le", "replace")
    if label == "utf16be":
        return raw.decode("utf-16-be", "replace")
    return raw.decode("latin-1", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", nargs="?", default="mem.raw")
    ap.add_argument("--min", type=int, default=6, help="minimum character count")
    ap.add_argument("--grep", default=None, help="only print strings matching this regex")
    ap.add_argument("--encodings", default="ascii,utf16le",
                    help="comma list of ascii,utf16le,utf16be")
    ap.add_argument("--unique", action="store_true", help="suppress duplicates")
    args = ap.parse_args()

    encs = {e.strip() for e in args.encodings.split(",") if e.strip()}
    pats = build_patterns(args.min, encs)
    if not pats:
        print("no valid encodings selected", file=sys.stderr)
        return 2
    needle = re.compile(args.grep) if args.grep else None
    seen: set[str] = set()

    try:
        for start, buf in iter_chunks(args.image):
            for label, pat, _stride in pats:
                for m in pat.finditer(buf):
                    text = decode(label, m.group(0))
                    if needle and not needle.search(text):
                        continue
                    if args.unique:
                        if text in seen:
                            continue
                        seen.add(text)
                    print(f"{start + m.start():>14d}  {label:<8s}  {text}")
    except FileNotFoundError:
        print(f"no such file: {args.image}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Find task_struct.comm candidates in a raw Linux memory image without any symbols.

comm is `char comm[16]`: a short printable process name, NUL-terminated and NUL-padded
to 16 bytes, 8-byte aligned inside a slab-allocated task_struct. Real task structs are
allocated near each other, so genuine hits come in dense clusters; isolated hits are noise.

    python3 comm_scan.py mem.lime --cluster 3
"""
from __future__ import annotations

import argparse
import collections
import re
import sys

CHUNK = 16 * 1024 * 1024
NAME_RE = re.compile(rb"^[A-Za-z0-9_.:@+\-/\[\]]{2,15}$")
# names that show up in almost every Linux dump - a cluster containing one is very likely real
KERNEL_THREADS = {
    b"swapper/0", b"kthreadd", b"ksoftirqd/0", b"rcu_sched", b"rcu_preempt", b"migration/0",
    b"kworker/0:0", b"kworker/u2:0", b"kcompactd0", b"khugepaged", b"kswapd0", b"systemd",
    b"init", b"jbd2/sda1-8", b"ksmd", b"watchdog/0", b"kdevtmpfs", b"oom_reaper",
}


def candidates(path: str, align: int):
    """Yield (offset, name_bytes) for every 16-byte slot that looks like comm."""
    with open(path, "rb") as fh:
        base = 0
        carry = b""
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                return
            buf = carry + chunk
            start = base - len(carry)
            limit = len(buf) - 16
            off = (-start) % align if start < 0 else 0
            for i in range(off, max(off, limit), align):
                slot = buf[i:i + 16]
                if len(slot) < 16:
                    break
                nul = slot.find(b"\x00")
                if nul < 2:
                    continue
                if slot[nul:] != b"\x00" * (16 - nul):
                    continue
                name = slot[:nul]
                if not NAME_RE.match(name):
                    continue
                yield start + i, name
            base += len(chunk)
            carry = buf[-16:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", nargs="?", default="mem.lime")
    ap.add_argument("--align", type=int, default=8, help="scan alignment in bytes")
    ap.add_argument("--window", type=int, default=0x40000,
                    help="cluster window in bytes")
    ap.add_argument("--cluster", type=int, default=3,
                    help="minimum hits in a window before the window is reported")
    args = ap.parse_args()

    buckets: dict[int, list[tuple[int, bytes]]] = collections.defaultdict(list)
    try:
        for off, name in candidates(args.image, args.align):
            buckets[off // args.window].append((off, name))
    except FileNotFoundError:
        print(f"no such file: {args.image}", file=sys.stderr)
        return 1

    reported = 0
    for bucket in sorted(buckets):
        hits = buckets[bucket]
        names = {n for _, n in hits}
        anchored = bool(names & KERNEL_THREADS)
        if len(hits) < args.cluster and not anchored:
            continue
        reported += 1
        tag = "  [anchored by known kernel thread]" if anchored else ""
        print(f"\n=== window 0x{bucket * args.window:012x}  ({len(hits)} candidates){tag}")
        for off, name in hits[:40]:
            print(f"  0x{off:012x}  {name.decode('latin-1')}")
        if len(hits) > 40:
            print(f"  ... {len(hits) - 40} more")
    if not reported:
        print("no clusters found; lower --cluster or widen --window", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **LiME `format=lime` is not raw.** Either strip the 32-byte headers per range or use
  `format=padded` at acquisition. Scanning a lime file with `strings` still works; carving files
  across a range boundary does not.
- **Physical holes**: raw dumps contain the memory-mapped I/O holes as zeros. Offsets in a raw dump
  are physical addresses only in `padded` format.
- A **container** memory dump is just the host's memory - every namespace is in there.
- Symbol tables are per **build**, not per version. `5.15.0-91-generic` and `5.15.0-92-generic`
  need different ISFs.
- `linux.bash.Bash` only recovers history still in the bash process' heap; a shell that exited and
  whose memory was reused is gone. Fall back to string scanning near `HISTFILE`.
- Big-endian / ARM dumps: vol3 supports them if the ISF does; `strings -eb` matters there.
- Do not run `binwalk -e` on a multi-gigabyte dump without a disk-space check; it can produce
  hundreds of gigabytes of false extractions. Use `binwalk` (list only) first.

## Tools

`volatility3` (`linux.*`, `mac.*`, `banners.Banners`), `dwarf2json`, `LiME`, `AVML`,
`binwalk`, `foremost`, `photorec`, `bulk_extractor`, `strings`, `xxd`, `dd`, `MemProcFS`.

## References

- `vol3 -f img -h` lists the exact `linux.*` plugin class names your build ships.
- The dwarf2json README documents the `linux` and `mac` subcommands and their flags.
