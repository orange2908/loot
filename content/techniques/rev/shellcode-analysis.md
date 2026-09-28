---
title: "Shellcode Analysis - Blob to Disassembly to Behaviour"
category: rev
subcategory: shellcode
type: technique
tags: [shellcode, scdbg, speakeasy, unicorn, capstone, ndisasm, getpc, peb-walk, api-hashing, ror13, xor-decoder, shikata-ga-nai, egghunter, msfvenom, staged-payload, position-independent-code]
difficulty: medium
summary: "Disassemble a headerless payload, emulate it to get past the decoder stub, and resolve ROR13 API hashes back to Windows function names."
when_to_use:
  - "You have a raw byte blob with no headers that looks like code"
  - "A document or exploit dropped a payload and you need its behaviour, not its bytes"
  - "The blob starts with a decoder loop and the real code is encrypted"
  - "You see constants like 0x726774c or a gs:[0x60] dereference"
tools: [ndisasm, objdump, capstone, scdbg, speakeasy, unicorn, gdb, radare2]
related: [windows-pe-reversing, packers-and-unpacking, unicorn-qiling-emulation, firmware-raw-blob-loading, triage-unknown-binary, anti-debug-bypass]
---

## TL;DR

Shellcode is position-independent code with no headers. Disassemble it at several offsets
and bitnesses until one produces sane instructions; if it starts with a decoder loop,
emulate it (scdbg, speakeasy, Unicorn) and dump the decoded stage. On Windows payloads the
API calls are resolved by hashing export names - build a hash table of known API names and
look the constants up.

## Recognise it

| Signal | Meaning |
|---|---|
| `90 90 90 90 ...` | NOP sled in front of the payload |
| `e8 00 00 00 00 5?` | `call $+5; pop reg` - GetPC, the payload learns its own address |
| `eb xx ... e8 <neg> ... 5?` | jmp/call/pop: a string is embedded after the `call` |
| `d9 ee d9 74 24 f4 5?` | `fldz; fnstenv [esp-0xc]; pop` - the FPU GetPC variant |
| `64 8b ?? 30` / `65 48 8b ?? 60` | PEB access via fs:[0x30] (x86) / gs:[0x60] (x64) |
| `0f 05` / `cd 80` / `01 00 00 d4` | x86-64 `syscall` / x86 `int 0x80` / AArch64 `svc #0` |
| `31 c0 50 68 2f 2f 73 68` | the classic `execve("/bin//sh")` stub |
| a tight loop with `xor`/`add` and a counter | decoder stub |
| `bb <4 bytes>` then `d9 74 24 f4` | shikata_ga_nai key + FPU GetPC |
| low-entropy prologue, high-entropy tail | encoded payload behind a stub |

```sh
# Shape check
xxd -l 64 sc.bin
python3 -c "
import sys, collections, math
d = open(sys.argv[1],'rb').read(); c = collections.Counter(d); n = len(d)
print('len', n, 'entropy', round(-sum(v/n*math.log2(v/n) for v in c.values()), 3))
print('0x90 bytes:', d.count(b'\x90'))" sc.bin
```

## Disassembling a raw blob

```sh
# ndisasm (nasm package) - the fastest first look
ndisasm -b 64 sc.bin | head -60
ndisasm -b 32 sc.bin | head -60
ndisasm -b 64 -o 0x400000 sc.bin        # pretend it is loaded at an address
ndisasm -b 64 -e 12 sc.bin              # skip 12 bytes (past a header or sled)
# objdump on raw bytes
objdump -D -b binary -m i386:x86-64 sc.bin
objdump -D -b binary -m i386 sc.bin
objdump -D -b binary -m aarch64 sc.bin
# radare2
r2 -a x86 -b 64 -m 0 sc.bin -c 'pd 60'
rasm2 -a x86 -b 64 -D -f sc.bin
# assemble a comparison
rasm2 -a x86 -b 64 'mov rax, 60; syscall'
```

Try every alignment: shellcode often begins a few bytes into a blob (after an egg or a
length field). If instructions look insane at offset 0, step forward one byte at a time for
the first 16 offsets and look for the one where the GetPC/decoder prologue appears. A quick
scorer with capstone:

```python
#!/usr/bin/env python3
"""scdis.py - score (arch, offset) combinations for a raw blob and disassemble the best.

    pip install capstone
    python3 scdis.py sc.bin                       # auto-detect
    python3 scdis.py sc.bin --arch x64 --skip 12 --base 0x400000
"""
import argparse

from capstone import (CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
                      CS_MODE_ARM, CS_MODE_THUMB, Cs)

MODES = {"x86": (CS_ARCH_X86, CS_MODE_32), "x64": (CS_ARCH_X86, CS_MODE_64),
         "arm": (CS_ARCH_ARM, CS_MODE_ARM), "thumb": (CS_ARCH_ARM, CS_MODE_THUMB),
         "arm64": (CS_ARCH_ARM64, CS_MODE_ARM)}
# Instructions that almost never appear in real code - a high count means wrong mode/data.
JUNK = {"(bad)", "insb", "outsb", "outsd", "insd", "aaa", "aad", "aam", "das", "daa",
        "bound", "arpl", "lds", "les", "salc", "hlt", "icebp", "in", "out"}


def score(data, mode, base):
    md = Cs(*MODES[mode])
    covered = junk = 0
    for ins in md.disasm(data, base):
        covered += ins.size
        junk += ins.mnemonic in JUNK
    return covered, junk


def dump(data, mode, base, limit):
    for n, ins in enumerate(Cs(*MODES[mode]).disasm(data, base)):
        print("%#010x  %-24s %s %s" % (ins.address, ins.bytes.hex(" "),
                                       ins.mnemonic, ins.op_str))
        if n + 1 >= limit:
            break


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("blob")
    ap.add_argument("--arch", choices=sorted(MODES))
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--skip", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args()

    with open(args.blob, "rb") as fh:
        data = fh.read()[args.skip:]
    if args.arch:
        dump(data, args.arch, args.base, args.limit)
        return 0

    best = None
    for mode in MODES:
        for skip in range(8):
            covered, junk = score(data[skip:], mode, args.base)
            ratio = covered / max(len(data) - skip, 1)
            if ratio > 0.9 and junk < 5:
                print("plausible: --arch %s --skip %d (junk=%d)" % (mode, skip, junk))
            if best is None or (ratio, -junk) > best[0]:
                best = ((ratio, -junk), mode, skip)
    _key, mode, skip = best
    print("\n[+] best: --arch %s --skip %d\n" % (mode, skip))
    dump(data[skip:], mode, args.base, args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Emulating it

Static reading stops working the moment there is a decoder stub. Emulate instead.

```sh
# scdbg (libemu): x86 shellcode emulation with a Windows API call report
scdbg -f sc.bin                     # emulate from offset 0
scdbg -f sc.bin -s -1               # unlimited steps
scdbg -f sc.bin /findsc             # brute force the entry offset
scdbg -f sc.bin -s -1 -d            # dump the decoded buffer to sc.bin.unpack
#   4010cd  LoadLibraryA(ws2_32)
#   4010e5  WSASocket(af=2, tp=1, proto=0)
#   4010f1  connect(h=42, host: 10.0.0.1, port: 4444)

# speakeasy (Mandiant): modern x86/x64 Windows user- and kernel-mode emulation
speakeasy -t sc.bin -r -a x64
speakeasy -t sc.bin -r -a x86 -o report.json

# Linux shellcode: wrap it in an ELF (script below) and run it in a container
python3 sc2elf.py sc.bin sc.elf && chmod +x sc.elf && gdb -q ./sc.elf
```

Unicorn when the canned tools fail (unusual architecture, custom syscalls):

```python
#!/usr/bin/env python3
"""scemu.py - emulate x86-64 shellcode with Unicorn, log syscalls, dump the decoded stage.

    python3 scemu.py sc.bin [--trace]
"""
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_MODE_64, Uc
from unicorn.x86_const import (UC_X86_INS_SYSCALL, UC_X86_REG_RAX, UC_X86_REG_RDI,
                               UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSI,
                               UC_X86_REG_RSP)

BASE, STACK, SIZE = 0x400000, 0x7FFF0000, 0x100000
SYSCALLS = {0: "read", 1: "write", 2: "open", 9: "mmap", 10: "mprotect", 41: "socket",
            42: "connect", 59: "execve", 60: "exit", 101: "ptrace"}


def main():
    if len(sys.argv) < 2:
        print("usage: scemu.py sc.bin [--trace]")
        return 1
    with open(sys.argv[1], "rb") as fh:
        code = fh.read()

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BASE, SIZE)
    uc.mem_map(STACK - SIZE, SIZE * 2)
    uc.mem_write(BASE, code)
    uc.reg_write(UC_X86_REG_RSP, STACK)

    def on_syscall(u, _user):
        num = u.reg_read(UC_X86_REG_RAX)
        args = [u.reg_read(r) for r in (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX)]
        print("[syscall] %s(%#x, %#x, %#x)" % (SYSCALLS.get(num, "sys_%d" % num), *args))
        if num == 59:                                   # execve: show the path
            try:
                raw = bytes(u.mem_read(args[0], 64)).split(b"\x00")[0]
                print("           path = %r" % raw.decode(errors="replace"))
            except Exception:
                pass
        if num == 60:
            u.emu_stop()
        u.reg_write(UC_X86_REG_RAX, 0)                  # pretend it succeeded

    uc.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
    if "--trace" in sys.argv:
        uc.hook_add(UC_HOOK_CODE,
                    lambda u, a, s, _x: print("  %#010x: %s"
                                              % (a, bytes(u.mem_read(a, s)).hex(" "))))
    try:
        uc.emu_start(BASE, BASE + len(code), timeout=5_000_000, count=2_000_000)
    except Exception as exc:
        print("[!] stopped at %#x: %s" % (uc.reg_read(UC_X86_REG_RIP), exc))

    decoded = bytes(uc.mem_read(BASE, len(code)))
    if decoded != code:
        out = sys.argv[1] + ".decoded"
        with open(out, "wb") as fh:
            fh.write(decoded)
        print("[+] memory changed - decoded stage written to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Running Linux shellcode under gdb

```python
#!/usr/bin/env python3
"""sc2elf.py - wrap raw x86-64 shellcode in a minimal Linux ELF (hand-built headers).

    python3 sc2elf.py sc.bin sc.elf && chmod +x sc.elf && gdb -q ./sc.elf
    (gdb) starti        # stops on the first shellcode instruction

The segment is mapped RWX so self-modifying decoders work. Run it in a container.
"""
import struct
import sys

BASE, EHDR, PHDR = 0x400000, 64, 56


def build(code: bytes, base: int = BASE) -> bytes:
    entry = base + EHDR + PHDR
    filesz = EHDR + PHDR + len(code)
    ehdr = (b"\x7fELF"            # magic
            b"\x02\x01\x01\x00"   # ELFCLASS64, little-endian, version 1, SysV
            + b"\x00" * 8         # padding
            + struct.pack("<HHI", 2, 0x3E, 1)          # ET_EXEC, EM_X86_64, version
            + struct.pack("<QQQ", entry, EHDR, 0)      # e_entry, e_phoff, e_shoff
            + struct.pack("<IHHHHHH", 0, EHDR, PHDR, 1, 64, 0, 0))
    assert len(ehdr) == EHDR, len(ehdr)
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, base, base,
                       filesz, filesz + 0x1000, 0x1000)   # PT_LOAD, RWX
    assert len(phdr) == PHDR, len(phdr)
    return ehdr + phdr + code


def main():
    if len(sys.argv) != 3:
        print("usage: sc2elf.py <shellcode.bin> <out.elf>")
        return 1
    with open(sys.argv[1], "rb") as fh:
        blob = build(fh.read())
    with open(sys.argv[2], "wb") as fh:
        fh.write(blob)
    print("[+] %s: %d bytes, entry %#x" % (sys.argv[2], len(blob), BASE + EHDR + PHDR))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # self-test: exit(42) = mov eax,60; mov edi,42; syscall
        sc = b"\xb8\x3c\x00\x00\x00\xbf\x2a\x00\x00\x00\x0f\x05"
        elf = build(sc)
        assert elf[:4] == b"\x7fELF"
        assert struct.unpack_from("<H", elf, 18)[0] == 0x3E          # EM_X86_64
        assert struct.unpack_from("<Q", elf, 24)[0] == BASE + 120    # e_entry
        assert elf[120:] == sc
        print("[+] sc2elf self-test OK (the ELF would exit with code 42)")
        raise SystemExit(0)
    raise SystemExit(main())
```

`starti` stops on the first instruction; `x/20i $pc` then gives a live disassembly with real
addresses and `catch syscall` shows exactly what the payload does.

## Windows shellcode: PEB walk and API hashing

Position-independent Windows payloads cannot import anything, so they walk the PEB to find
`kernel32.dll` and hash export names to locate functions.

```asm
; x64                                   ; x86
mov rax, gs:[0x60]      ; PEB           mov eax, fs:[0x30]      ; PEB
mov rax, [rax + 0x18]   ; PEB->Ldr      mov eax, [eax + 0x0C]   ; PEB->Ldr
mov rsi, [rax + 0x20]   ; InMemoryOrder mov esi, [eax + 0x14]   ; InMemoryOrder
lodsq                   ; first entry   ; walk the list to kernel32.dll
```

Offsets: x86 `fs:[0x30]` = PEB, `PEB+0x0C` = Ldr, `Ldr+0x0C` = InLoadOrderModuleList,
`Ldr+0x14` = InMemoryOrderModuleList; x64 `gs:[0x60]` = PEB, `PEB+0x18` = Ldr,
`Ldr+0x20` = InMemoryOrderModuleList. From a module entry, `+0x30` (x64) / `+0x18` (x86) is
the DLL base.

```python
#!/usr/bin/env python3
"""ror13.py - compute and reverse the ROR13 API hashes used by Metasploit-style shellcode.

    python3 ror13.py 0x726774c               # identify a constant
    python3 ror13.py --name kernel32.dll WinExec
    python3 ror13.py --scan sc.bin           # find every known hash inside a blob

The block_api hash is ror13 over the UPPERCASE module name in UTF-16LE (with the trailing
NUL) plus ror13 over the ASCII function name (with its trailing NUL), truncated to 32 bits.
"""
import struct
import sys

MODULES = ["kernel32.dll", "ntdll.dll", "ws2_32.dll", "advapi32.dll", "user32.dll",
           "wininet.dll", "urlmon.dll", "shell32.dll", "msvcrt.dll", "crypt32.dll"]
FUNCTIONS = [
    "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect", "CreateProcessA",
    "WinExec", "ExitProcess", "ExitThread", "CreateFileA", "WriteFile", "ReadFile",
    "CloseHandle", "CreateThread", "WaitForSingleObject", "GetModuleHandleA", "Sleep",
    "TerminateProcess", "GetCurrentProcess", "WSAStartup", "WSASocketA", "connect",
    "bind", "listen", "accept", "recv", "send", "closesocket", "InternetOpenA",
    "InternetOpenUrlA", "InternetReadFile", "URLDownloadToFileA", "ShellExecuteA",
    "RegOpenKeyExA", "RegSetValueExA", "CryptAcquireContextA", "CryptDecrypt",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "RtlExitUserThread",
]


def ror(value: int, count: int, bits: int = 32) -> int:
    mask = (1 << bits) - 1
    value &= mask
    count %= bits
    return ((value >> count) | (value << (bits - count))) & mask


def ror13_hash(data: bytes) -> int:
    result = 0
    for byte in data:
        result = (ror(result, 13) + byte) & 0xFFFFFFFF
    return result


def module_hash(name: str) -> int:
    return ror13_hash(name.upper().encode("utf-16le") + b"\x00\x00")


def function_hash(name: str) -> int:
    return ror13_hash(name.encode() + b"\x00")


def table() -> dict:
    out = {}
    for mod in MODULES:
        mh = module_hash(mod)
        for fn in FUNCTIONS:
            out[(mh + function_hash(fn)) & 0xFFFFFFFF] = "%s!%s" % (mod, fn)
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    if args[0] == "--name":
        value = (module_hash(args[1]) + function_hash(args[2])) & 0xFFFFFFFF
        print("%s!%s -> %#010x" % (args[1], args[2], value))
        return 0

    known = table()
    if args[0] == "--scan":
        with open(args[1], "rb") as fh:
            data = fh.read()
        found = 0
        for off in range(len(data) - 3):
            (value,) = struct.unpack_from("<I", data, off)
            if value in known:
                print("  %#06x: %#010x  %s" % (off, value, known[value]))
                found += 1
        print("[+] %d known API hash(es) found" % found)
        return 0

    for arg in args:
        value = int(arg, 0)
        print("%#010x -> %s" % (value, known.get(value, "<unknown - extend the lists>")))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        assert ror(1, 1) == 0x80000000
        win = (module_hash("kernel32.dll") + function_hash("WinExec")) & 0xFFFFFFFF
        lla = (module_hash("kernel32.dll") + function_hash("LoadLibraryA")) & 0xFFFFFFFF
        assert win == 0x876F8B31, hex(win)
        assert lla == 0x0726774C, hex(lla)
        print("[+] ror13 self-test OK (WinExec=%#010x, LoadLibraryA=%#010x)" % (win, lla))
        raise SystemExit(0)
    raise SystemExit(main())
```

Other hashes in the wild: `ROL7 + xor`, CRC32, FNV-1a and djb2. If ROR13 does not match,
swap the hash function - the API name list stays the same.

## Decoder stubs

| Encoder | Recognition | Handling |
|---|---|---|
| Plain XOR | `xor byte [esi+ecx], key; loop` | xor it back in Python |
| Multi-byte XOR | a 4-byte key constant near the loop | repeating-key xor |
| `shikata_ga_nai` | `bb <key>` + `d9 74 24 f4` FPU GetPC, self-modifying additive feedback | emulate; never decode by hand |
| `x86/alpha_mixed` | the whole payload is `[A-Za-z0-9]` | emulate |
| `x86/call4_dword_xor` | `call $+4` then a dword xor loop | trivial in Python |
| UUID / IPv4 obfuscation | a list of `192.168.1.2`-looking strings or UUIDs | convert back to bytes |
| Base64 + XOR | readable base64 blob | decode, then xor |

```python
#!/usr/bin/env python3
"""xordec.py - recover a 1-4 byte XOR key from an encoded payload, and write the plaintext.

Heuristic: the decoded stage nearly always contains a marker (a PEB access, a URL,
a syscall stub, 'cmd.exe').   Usage: python3 xordec.py encoded.bin
"""
import itertools
import sys

MARKERS = [b"\x64\x8b", b"\x65\x48\x8b", b"http", b"cmd.exe", b"kernel32",
           b"This program", b"\x0f\x05", b"\xcd\x80"]


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def crack(data: bytes, maxlen: int = 4):
    """Shortest key whose decoding contains a marker, best score first."""
    for klen in range(1, maxlen + 1):
        hits = [(sum(xor(data, bytes(k)).count(m) for m in MARKERS), bytes(k))
                for k in itertools.product(range(256), repeat=klen)]
        hits = sorted((h for h in hits if h[0]), reverse=True)
        if hits:
            return [(key, score) for score, key in hits[:10]]
    return []


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
    for key, score in crack(data):
        out = "%s.dec_%s" % (sys.argv[1], key.hex())
        with open(out, "wb") as fh:
            fh.write(xor(data, key))
        print("key=%s score=%d -> %s" % (key.hex(), score, out))
    return 0


if __name__ == "__main__":
    sample = b"\x64\x8b\x35\x30\x00\x00\x00" + b"cmd.exe\x00" * 4
    assert crack(xor(sample, b"\x5a"))[0][0] == b"\x5a"
    if len(sys.argv) == 1:
        print("[+] xordec self-test OK (recovered single-byte key 0x5a)")
        raise SystemExit(0)
    raise SystemExit(main())
```

## Staged vs stageless, egg hunters, C2 extraction

- **Stageless**: the whole payload is in the blob, including the C2 host and port. Find the
  `connect` call and the `sockaddr_in` built just before it - family `0x0002`, then a
  big-endian port, then 4 raw IP bytes.
- **Staged**: the blob only connects, `recv`s N bytes into a fresh `VirtualAlloc`ed buffer
  and jumps to it. There is nothing else to find locally; the payload lives on the server.
- **Egg hunter**: a small loop scanning memory for an 8-byte tag (usually the same 4 bytes
  twice, e.g. `w00tw00t`) that jumps just past it. Recognise it by memory-probing via
  `NtAccessCheckAndAuditAlarm` / `access()` plus a constant compared twice.

```sh
# Convert the constants you saw in the disassembly back into an endpoint
python3 -c "
import socket, struct
print(socket.inet_ntoa(struct.pack('<I', 0x0100007f)))       # IP constant
print('port', struct.unpack('>H', struct.pack('<H', 0x5c11))[0])"
```

## Variants & pitfalls

- **Always analyse in a VM or container.** A mistake turns "disassembly" into execution.
- **Wrong bitness** produces plausible-looking nonsense. Compare x86 and x64 output; the
  right one has a coherent GetPC or PEB prologue.
- **The blob may be inside something else**: an OLE stream, a JS `unescape("%u...")`, a
  base64 PowerShell blob. Decode the container first.
- **scdbg is 32-bit only**; use speakeasy or Unicorn for x64.
- **Null-byte-free or alphanumeric constraints** shape the code (`xor eax,eax` instead of
  `mov eax,0`, strings built with `push`). That is a hint the payload came from an exploit
  with a character filter.
- **Self-modifying decoders need a writable page** - `sc2elf.py` marks the segment RWX.
- **An emulator's API log is not complete**: it stops at the first unimplemented API.
  Cross-check against a disassembly.

## Tools

- `ndisasm`, `objdump -b binary`, `rasm2 -D`, `capstone` - disassembly.
- `scdbg` (libemu) - x86 emulation with an API call report.
- `speakeasy` - x86/x64 Windows user- and kernel-mode emulation.
- `unicorn` - any architecture, full control.
- `shellcode2exe`, `libemu`/`sctest` - alternative runners.
- `msfvenom --list encoders` - to recognise what you are looking at.
- `CyberChef` - quick hex/base64/UUID/IPv4 decoding of wrapped blobs.

## References

- Metasploit `block_api.asm` in the metasploit-framework repository: the canonical ROR13
  hash routine and the PEB-walking prologue reproduced above.
- Microsoft documentation for the PEB and PEB_LDR_DATA structures.
- Intel SDM for the `syscall` / `int 0x80` transitions.
