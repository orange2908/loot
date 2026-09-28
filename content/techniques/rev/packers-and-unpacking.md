---
title: "Packers and Unpacking - UPX, Custom Crypters, Finding the OEP"
category: rev
subcategory: packers
type: technique
tags: [packers, unpacking, upx, oep, entry-point, entropy, memory-dump, scylla, iat-rebuild, mprotect, virtualprotect, self-modifying-code, proc-mem, gcore, aspack, themida, dumping, crypter]
difficulty: medium
summary: "Spot a packed binary by entropy and a 3-import table, then run it to the OEP and dump the unpacked image from memory."
when_to_use:
  - "strings shows almost nothing and the import table has 3 entries"
  - "Section names are UPX0/UPX1/.aspack/.petite, or the entry point is outside .text"
  - "Entropy of a section is above ~7.2 bits/byte"
  - "The decompiler shows a tiny loop that writes into its own code section"
tools: [upx, gdb, radare2, ghidra, x64dbg, scylla, binwalk, python]
related: [triage-unknown-binary, binary-patching, anti-debug-bypass, obfuscation-deobfuscation, windows-pe-reversing, firmware-raw-blob-loading]
---

## TL;DR

A packer replaces the program with a small stub plus a compressed/encrypted blob. The stub
allocates memory, decompresses into it, rebuilds the imports, and jumps to the Original
Entry Point. You do not need to understand the stub: run until the decompression is done,
dump memory, fix up the headers, and analyse the dump.

## Recognise it

| Signal | How to check |
|---|---|
| High entropy | `ent`, `binwalk -E`, or the python scanner below (>7.2 bits/byte = compressed) |
| Tiny import table | `nm -D ./bin` shows 3-5 imports; `rabin2 -i bin.exe` shows only `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc` |
| Odd section names | `UPX0`/`UPX1`/`UPX!`, `.aspack`, `.adata`, `.petite`, `.nsp0`, `.themida`, `.vmp0`, `.enigma1` |
| W+X section | `readelf -l -W` shows a `RWE` segment; `rabin2 -S bin.exe` shows a writable+executable section |
| Entry point outside .text | `readelf -h` entry vs `readelf -S` `.text` range |
| Virtual size >> raw size | PE: `SizeOfRawData` 0 for the first section, huge `VirtualSize` |
| No strings | `strings -a ./bin | wc -l` is tiny and all of it is stub noise |
| `file` output | "UPX compressed", "packed" |

```sh
# Quick triage battery
file ./bin                                    # sometimes names the packer outright
readelf -h ./bin | grep Entry                 # entry point address
readelf -S -W ./bin                           # look for UPX0/UPX1 or a single RWE section
readelf -l -W ./bin | grep -A1 LOAD           # RWE flags = self-modifying
binwalk -E ./bin                              # entropy plot; a flat 8.0 plateau = packed
strings -a ./bin | grep -aiE 'upx|aspack|petite|themida|vmprotect|enigma|mpress|pecompact'
# Windows PE
rabin2 -I bin.exe; rabin2 -S bin.exe; rabin2 -i bin.exe
```

`Detect It Easy` (`diec -n bin.exe`) and `pyinstxtractor`/`PEiD` signatures identify most
commercial packers by their stub bytes.

## UPX - the easy case

```sh
# 99% of CTF packing: just decompress
upx -d ./packed -o ./unpacked
# Confirm the result is sane
file ./unpacked && strings -a ./unpacked | head
```

When `upx -d` fails with "NotPackedException" or "CantUnpackException", the header was
tampered with. Common tampering and fixes:

1. **Magic string removed**: UPX stores `UPX!` (`55 50 58 21`) three times - in the
   `l_info` header, `p_info`, and at the end of file. Restore them:

```sh
# Find what is left of the magic and see the packed-header layout
xxd ./packed | grep -i -n 'UPX'
# Patch the magic back in at the offsets where it was zeroed (example offset)
printf 'UPX!' | dd of=./packed bs=1 seek=$((0xEC)) conv=notrunc
```

2. **Version byte changed**: UPX refuses versions it does not know. The `l_info` struct is
   `{ uint32 l_checksum; uint32 l_magic /* "UPX!" */; uint16 l_lsize; uint8 l_version;
   uint8 l_format; }`. Set `l_version` to your local `upx --version` major value.
3. **Section names changed** from `UPX0/UPX1`: rename them back with a hex editor - UPX
   locates its data by name.
4. **Genuinely modified stub**: give up on `upx -d` and dump from memory (below). That
   always works.

## Manual unpacking - the general recipe

The universal trigger: **the unpacked code must be written to memory and made executable**.
Break on the moment that happens.

### Linux

```sh
# 1. Break on mprotect with PROT_EXEC and on any memory allocation
gdb -q ./packed
# (gdb) catch syscall mprotect
# (gdb) catch syscall mmap
# (gdb) run
# ... each hit: check the args
# (gdb) info registers rdi rsi rdx     # addr, len, prot  (4 = PROT_EXEC)
# 2. When PROT_EXEC appears on a region that was just written, the payload is plaintext
# (gdb) dump binary memory dump.bin 0x7ffff7f00000 0x7ffff7f20000
# 3. Or dump everything and pick later
# (gdb) gcore core.packed
```

Finding the OEP on Linux: set a breakpoint on the address the stub finally jumps to. The
UPX stub ends with a `jmp` to an address inside the (now decompressed) original image, far
from the stub. Single-step the tail:

```
(gdb) starti
(gdb) x/20i $pc
(gdb) break *<address of the final jmp>
(gdb) continue
(gdb) si                # now $pc is the OEP
(gdb) info proc mappings
```

### Windows (x64dbg)

1. Open the binary, it breaks at the stub entry (`EntryPoint`).
2. **ESP trick** (works for stubs that start with `pushad`): step over the `pushad`, then
   `Follow in Dump` -> ESP, select 4 bytes (or 8 on x64), right-click -> Breakpoint ->
   Hardware, Access. Run. The breakpoint hits at the matching `popad`, which is immediately
   before the tail jump to the OEP.
3. **Tail jump**: look for `jmp <far address>` / `push <addr>; ret` after the `popad`.
   Step into it - you are at the OEP.
4. Use the **Scylla** plugin: set the OEP field, click `IAT Autosearch`, `Get Imports`,
   `Dump`, then `Fix Dump` on the dumped file. This rebuilds the import table, without
   which the dump is useless in a disassembler.
5. Alternatively set a breakpoint on `VirtualProtect`/`VirtualAlloc`/`WriteProcessMemory`
   (`bp VirtualProtect`) and watch for an RWX allocation being filled.

## Code - entropy scanner (is it packed?)

```python
#!/usr/bin/env python3
"""entropy_scan.py - per-section and sliding-window Shannon entropy of a file.

Usage:
    python3 entropy_scan.py ./bin              # sliding window over the whole file
    python3 entropy_scan.py ./bin --sections   # per-ELF-section (needs pyelftools)

Rules of thumb (bits/byte):
    < 5.0   text, tables, padding
    6.0-7.0 normal compiled code
    > 7.2   compressed or encrypted
    ~8.0    random / strong crypto
"""
import math
import sys
from collections import Counter


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def sliding(path: str, window: int = 4096) -> None:
    with open(path, "rb") as fh:
        data = fh.read()
    print(f"{'offset':>10}  {'entropy':>7}  bar")
    packed_bytes = 0
    for off in range(0, len(data), window):
        chunk = data[off:off + window]
        ent = entropy(chunk)
        if ent > 7.2:
            packed_bytes += len(chunk)
        bar = "#" * int(ent * 6)
        print(f"{off:#010x}  {ent:7.3f}  {bar}")
    pct = 100.0 * packed_bytes / max(len(data), 1)
    print(f"\n[+] {pct:.1f}% of the file is above 7.2 bits/byte")
    if pct > 40:
        print("[!] likely packed or encrypted")


def sections(path: str) -> None:
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        print(f"{'section':<22} {'size':>10} {'entropy':>8}")
        for sec in elf.iter_sections():
            data = sec.data()
            if not data:
                continue
            flag = "  <-- PACKED?" if entropy(data) > 7.2 and len(data) > 1024 else ""
            print(f"{sec.name:<22} {len(data):>10} {entropy(data):>8.3f}{flag}")
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 0x5) == 0x5 and (seg["p_flags"] & 0x2):
                print(f"[!] RWE segment at {seg['p_vaddr']:#x} - self-modifying code")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    if "--sections" in sys.argv:
        sections(sys.argv[1])
    else:
        sliding(sys.argv[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Code - dump a live process's memory on Linux

```python
#!/usr/bin/env python3
"""memdump.py - dump mapped regions of a running process via /proc/<pid>/mem.

Usage:
    python3 memdump.py <pid>                       # list the maps
    python3 memdump.py <pid> --exec out/           # dump every executable region
    python3 memdump.py <pid> 0x7f0000000000 0x1000 # dump one range

Requires the same uid (or root) and, on most systems, ptrace_scope <= 1
(sudo sysctl -w kernel.yama.ptrace_scope=0 if attaching to an unrelated process).
"""
import os
import sys


def maps(pid: int) -> list[dict]:
    out = []
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as fh:
        for line in fh:
            fields = line.split()
            addrs, perms = fields[0], fields[1]
            start_s, end_s = addrs.split("-")
            out.append({
                "start": int(start_s, 16),
                "end": int(end_s, 16),
                "perms": perms,
                "path": fields[5] if len(fields) > 5 else "",
            })
    return out


def read_range(pid: int, start: int, size: int) -> bytes:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as fh:
        fh.seek(start)
        return fh.read(size)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    pid = int(sys.argv[1])
    regions = maps(pid)

    if len(sys.argv) == 2:
        for reg in regions:
            size = reg["end"] - reg["start"]
            print(f"{reg['start']:#018x}-{reg['end']:#018x} {reg['perms']} "
                  f"{size:>10} {reg['path']}")
        return 0

    if sys.argv[2] == "--exec":
        outdir = sys.argv[3] if len(sys.argv) > 3 else "dumps"
        os.makedirs(outdir, exist_ok=True)
        for reg in regions:
            if "x" not in reg["perms"]:
                continue
            size = reg["end"] - reg["start"]
            try:
                data = read_range(pid, reg["start"], size)
            except OSError as exc:
                print(f"[-] {reg['start']:#x}: {exc}")
                continue
            name = os.path.join(outdir, f"{reg['start']:016x}_{reg['perms']}.bin")
            with open(name, "wb") as fh:
                fh.write(data)
            print(f"[+] {name} ({len(data)} bytes) {reg['path']}")
        return 0

    start = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0)
    sys.stdout.buffer.write(read_range(pid, start, size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Workflow with it:

```sh
# 1. Start the packed binary stopped at its entry point
gdb -q -ex starti ./packed &
# 2. In gdb, run until the unpacking has finished (mprotect catchpoint, or a timer)
# 3. From another shell, dump every executable mapping
python3 memdump.py $(pgrep -n packed) --exec dumps/
# 4. The biggest new RX region that is not ld.so/libc is the unpacked image
ls -lS dumps/ | head
strings -a dumps/0000555555554000_r-xp.bin | head -40
```

## Code - a gdb script that stops the moment code becomes executable

```python
#!/usr/bin/env python3
"""oep_catch.py - gdb script: stop when mprotect makes a region executable and dump it.

Use:  gdb -q -x oep_catch.py ./packed
Then: (gdb) run
"""
try:
    import gdb  # type: ignore
except ImportError:
    gdb = None


class MprotectCatcher(gdb.Breakpoint if gdb else object):
    """Break on the mprotect PLT/libc symbol; report PROT_EXEC requests."""

    def __init__(self):
        super().__init__("mprotect")
        self.seen = 0

    def stop(self):
        frame = gdb.selected_frame()
        addr = int(frame.read_register("rdi"))
        length = int(frame.read_register("rsi"))
        prot = int(frame.read_register("rdx"))
        names = []
        if prot & 1:
            names.append("READ")
        if prot & 2:
            names.append("WRITE")
        if prot & 4:
            names.append("EXEC")
        print(f"[oep] mprotect({addr:#x}, {length:#x}, {'|'.join(names) or 'NONE'})")
        if prot & 4:
            self.seen += 1
            out = f"unpacked_{self.seen}_{addr:x}.bin"
            gdb.execute(f"dump binary memory {out} {addr:#x} {addr + length:#x}")
            print(f"[oep] dumped {length:#x} bytes to {out} - inspect it now")
            return True        # halt so you can look around
        return False


def install() -> None:
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set disable-randomization on")
    MprotectCatcher()
    print("[oep] armed: break on mprotect(PROT_EXEC) and auto-dump")


if gdb is not None:
    install()
else:
    print("oep_catch.py is a gdb script: gdb -q -x oep_catch.py ./packed")
```

## Custom crypters - decrypt in place

A typical CTF "custom packer" looks like this:

```c
/* .text is mapped RWX; the stub xors it with a key and jumps into it */
extern char __start_payload[], __stop_payload[];
int main(void) {
    size_t len = __stop_payload - __start_payload;
    mprotect((void *)((uintptr_t)__start_payload & ~0xFFFUL), len + 0x1000,
             PROT_READ | PROT_WRITE | PROT_EXEC);
    for (size_t i = 0; i < len; i++)
        __start_payload[i] ^= (char)(0x5A + (i & 0x0F));
    ((void (*)(void))__start_payload)();     /* tail jump = OEP */
    return 0;
}
```

Three ways to beat it, in increasing effort:

1. **Break after the loop and dump** (the script above).
2. **Reimplement the decryption in Python** - read the encrypted bytes from the file at the
   right offset, xor them, write the plaintext back into a copy of the binary, and load the
   result in Ghidra. This gives you a statically analysable file.
3. **Emulate the stub with Unicorn** and read the decrypted region out of the emulator -
   correct even if the key schedule is complicated. See `unicorn-qiling-emulation`.

```python
#!/usr/bin/env python3
"""static_decrypt.py - decrypt a packed region in the file itself and write a new binary.

Usage: python3 static_decrypt.py ./packed 0x2000 0x1c00 out.bin
       (file, file offset of the payload, length, output)
"""
import shutil
import sys


def transform(data: bytes) -> bytes:
    """Reimplementation of the stub's loop - edit to match your target."""
    return bytes(b ^ ((0x5A + (i & 0x0F)) & 0xFF) for i, b in enumerate(data))


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__)
        return 1
    src, off, length, dst = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), sys.argv[4]
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as fh:
        fh.seek(off)
        enc = fh.read(length)
        fh.seek(off)
        fh.write(transform(enc))
    print(f"[+] decrypted {length} bytes at {off:#x} -> {dst}")
    print("[+] now: strings -a", dst, "| head")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Analysing the dump

A raw memory dump has no headers. Load it as a flat blob at the address it was dumped from:

- **Ghidra**: `File > Import File`, Format `Raw Binary`, set Language (`x86:LE:64:default`),
  then in the Memory Map window set the block's start address to the dump address.
- **IDA**: `Load file > Binary file`, set the processor, then `Edit > Segments > Rebase
  program` to the dump address.
- **radare2**: `r2 -B 0x555555554000 -a x86 -b 64 dump.bin` then `aaa`.

For a PE dump, prefer a **Scylla-fixed dump**: it re-creates a valid PE header and IAT, so
Ghidra/IDA resolve API calls by name instead of showing `call [0x140003018]`.

See `firmware-raw-blob-loading` for choosing a base address when you do not know it.

## Variants & pitfalls

- **Anti-debug in the stub** is extremely common (see `anti-debug-bypass`): defeat it first
  or the stub will never unpack.
- **Multi-stage**: stage 1 decrypts stage 2 which decrypts stage 3. Keep the mprotect
  catchpoint armed and dump each time; stop when strings look like real code.
- **IAT is not rebuilt in a Linux dump**: PLT entries still point at the stub's resolver.
  Cross-reference with `/proc/<pid>/maps` and the library base addresses to resolve calls.
- **Dumping too early** gives you partially decrypted code; dumping too late (after the
  payload re-encrypts itself) gives ciphertext again. Dump at every PROT_EXEC event.
- **Section-size vs virtual-size mismatch** in PE dumps: memory is page-aligned to
  `VirtualAlignment` but the file is aligned to `FileAlignment`. Scylla handles this; doing
  it by hand means unmapping each section back to its raw offset.
- **VMProtect / Themida** do not have a clean OEP - the original code is turned into VM
  bytecode. Dumping gives you the VM, not the program. See `custom-vm-bytecode` and
  `obfuscation-deobfuscation`.
- **UPX with `--ultra-brute` or a modified stub** still unpacks with the memory-dump route.
- **PyInstaller/py2exe "packing" is not a packer** - it is an archive. See
  `python-bytecode-pyinstaller`.

## Tools

- `upx -d` - and `upx -l` to list what the file claims to contain.
- `Detect It Easy` (`diec`) / `PEiD` - packer signature identification.
- `x64dbg` + `Scylla` - the standard Windows unpack + IAT rebuild.
- `gdb` catchpoints, `gcore`, `/proc/<pid>/mem` - the Linux equivalents.
- `binwalk -E` / `ent` - entropy.
- `unicorn` / `qiling` - emulate the stub without running it natively.

## References

- UPX source: the `l_info` / `p_info` header structures and the `UPX!` magic.
- x64dbg documentation, Scylla plugin (`IAT Autosearch`, `Fix Dump`).
- `man 2 mprotect` - PROT_EXEC semantics that make the catchpoint universal.
