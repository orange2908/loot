---
title: "Tool - radare2 / rizin"
category: rev
subcategory: disassembler
type: tool
tags: [radare2, r2, rizin, cutter, disassembler, cli, reverse-engineering, r2pipe, patching, debugger, hexeditor, rev, pwn, binary-analysis]
summary: "The scriptable CLI reverse-engineering framework: disassemble, debug, patch and analyse binaries without leaving the terminal."
related: [rev-triage, ghidra, gdb-pwndbg-gef, pwn-triage]
---

## What it is

radare2 is a command-line binary analysis framework: disassembler, hex editor, debugger, patcher and scripting engine in one. `rizin` is a cleaner fork with the same command language; `Cutter` is rizin's Qt GUI (and bundles the Ghidra decompiler as `pdg`). Use it when you want answers in seconds without launching a GUI, and for anything you want to script.

## Install

```sh
# macOS
brew install radare2
brew install rizin           # the fork
# Linux: the recommended install is from git (distro packages lag badly)
git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
# Debian/Kali package
sudo apt install radare2
# Python bindings for scripting
pipx install r2pipe          # or: pip install r2pipe
# verify
r2 -v
```

## The invocations that matter

```sh
# 1. open with full analysis (the normal starting point)
r2 -AA ./chal
# 2. open in write mode, for patching
r2 -w ./chal
# 3. open a raw blob as 64-bit x86 shellcode
r2 -a x86 -b 64 -m 0 ./shellcode.bin
# 4. debug a process
r2 -d ./chal
# 5. run a command and exit (scriptable, no interactive session)
r2 -qc 'aaa; afl' ./chal
r2 -qc 'izz~flag' ./chal
r2 -qc 'pdf @ main' ./chal
# 6. disassemble one function as JSON for a script
r2 -qc 'aaa; pdfj @ main' ./chal | python3 -m json.tool
```

The commands you actually need, inside `r2`:

| Command | Meaning |
|---|---|
| `aaa` / `aaaa` | analyse all (the second form is more aggressive) |
| `afl` | list functions |
| `afl~main` | list functions matching "main" (`~` is grep) |
| `pdf @ main` | print disassembly of a function |
| `pdg @ main` | decompile (needs r2ghidra / is built in to rizin) |
| `s main` | seek to a symbol |
| `s 0x401000` | seek to an address |
| `iz` | strings in the data sections |
| `izz` | strings in the whole binary |
| `ii` | imports |
| `ie` | entrypoints |
| `iS` | sections |
| `iI` | binary info (arch, bits, PIE, NX, canary) |
| `axt @ sym.foo` | cross-references **to** this address |
| `axf @ sym.foo` | references **from** here |
| `/ flag` | search for a string |
| `/x 90909090` | search for hex bytes |
| `/R pop rdi` | search for a ROP gadget |
| `px 64 @ rsp` | hexdump |
| `pxw`, `pxq` | dump as words / quadwords |
| `wx 9090 @ 0x401234` | write hex bytes (needs `-w`) |
| `wa nop @ 0x401234` | write an assembled instruction |
| `wao nop` | nop out the current instruction |
| `V` then `p`/`P` | enter visual mode, cycle views |
| `VV` | visual graph mode |
| `db 0x401000` / `dc` / `dr` | breakpoint / continue / registers (debug mode) |
| `q` | quit |

Scripting with r2pipe:
```python
#!/usr/bin/env python3
"""List every function that references the string 'flag'."""
import json
import r2pipe

r2 = r2pipe.open("./chal")
r2.cmd("aaa")
for s in json.loads(r2.cmd("izzj"))["strings"]:
    if b"flag" in s["string"].encode(errors="ignore").lower():
        refs = json.loads(r2.cmd(f"axtj @ {s['vaddr']}") or "[]")
        for ref in refs:
            print(hex(s["vaddr"]), s["string"], "<-", ref.get("fcn_name"), hex(ref["from"]))
r2.quit()
```

Useful standalone binaries that ship with r2:
```sh
rabin2 -I ./chal          # checksec-equivalent info
rabin2 -z ./chal          # strings
rabin2 -i ./chal          # imports
rabin2 -s ./chal          # symbols
rabin2 -R ./chal          # relocations
rasm2 -a x86 -b 64 'mov rax, 59'        # assemble
rasm2 -a x86 -b 64 -d '48c7c03b000000'  # disassemble
rahash2 -a md5,sha256 ./chal
radiff2 -C a.bin b.bin    # function-level binary diff
ragg2 -i exec -x          # generate shellcode
```

## Gotchas

- The command language is terse and composable: `p`rint, `a`nalyse, `s`eek, `w`rite, `d`ebug, `i`nfo. Append `j` for JSON, `q` for quiet, `~` to grep, `~{}` to pretty-print JSON.
- `aaa` is required before most analysis commands. Without it, `afl` shows almost nothing.
- Writing requires `-w` at open time, or `oo+` to reopen in write mode.
- Addresses are relative to the mapped base; with PIE the default base is `0x100000` unless you `-B` it.
- `~` grep is applied by r2 itself, not by the shell - do not pipe to `grep` inside the r2 prompt.
- r2 and rizin have diverged: plugins for one do not work in the other. `r2ghidra` is for r2; rizin has the decompiler built in.
- Distro packages are often years old and missing commands. Install from git if something in a tutorial does not exist.
- Visual mode (`V`) is modal; `q` backs out one level at a time.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You want good decompilation | Ghidra (`ctfbrain search ghidra`), IDA, Binary Ninja |
| You want a GUI over the same engine | Cutter |
| Quick disassembly only | `objdump -d -M intel --no-show-raw-insn` |
| Quick strings/sections | `strings`, `readelf -a`, `nm -D` |
| Debugging | `gdb` with pwndbg or GEF (`ctfbrain search gdb-pwndbg-gef`) |
| ROP gadgets | `ROPgadget`, `ropper` |
| Binary diffing | `bindiff`, `diaphora` |
