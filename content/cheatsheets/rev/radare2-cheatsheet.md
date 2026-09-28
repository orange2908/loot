---
title: "radare2 - The 80 Commands That Matter"
category: rev
subcategory: radare2
type: cheatsheet
tags: [radare2, r2, rizin, cutter, r2pipe, disassembler, rabin2, rasm2, radiff2, rafind2, ragg2, visual-mode, patching, debugging, xrefs, rop]
summary: "radare2 in learning order: open, analyse, seek, print, search, flag, write, debug - plus r2pipe scripting and the rizin/Cutter equivalents."
tools: [radare2, rizin, cutter, r2pipe]
related: [ida-r2-binja-workflow, ghidra-cheatsheet, gdb-reversing-cheatsheet, binary-patching, triage-unknown-binary, shellcode-analysis]
---

## 0. The mental model

Every command is a letter tree: the first letter is the subsystem (`a` analysis, `p` print,
`s` seek, `w` write, `d` debug, `f` flags, `/` search, `e` config), the following letters
narrow it down. Append `?` to any prefix to list its children, `j` for JSON, `q` for quiet,
`*` for r2-command output.

## 1. Opening files

```sh
# Open read-only with full analysis - the usual starting point
r2 -A ./chall
# No analysis / write mode / debug mode
r2 ./chall ; r2 -w ./chall ; r2 -d ./chall
# Debug with arguments, or attach to a gdbserver
r2 -d ./chall -- arg1 arg2
r2 -d gdb://localhost:1234
# Raw blob: architecture, bits, map address (see firmware-raw-blob-loading)
r2 -a arm -b 16 -m 0x08000000 firmware.bin
r2 -a mips -b 32 -e cfg.bigendian=true blob.bin
# Scripting: run commands and quit
r2 -q -c 'aaa; afl' ./chall
r2 -q -c 'izz~flag' ./chall
# Treat the file as raw bytes (no header parsing); set config at launch
r2 -n ./chall
r2 -e asm.syntax=intel -e scr.color=3 ./chall
```

## 2. Help, grep and pipes

```
?                 # the most important command
a?  p?  s?  w?  d?  /?      # list the children of a prefix
?*~xref           # search the whole help text
afl~main          # internal grep on any command's output
afl~main,check    # OR of two patterns
afl~[0]           # first column only
pdf~call[2]       # column 2 of matching lines
izz~-e boring     # invert the match
afl | wc -l       # pipe to a shell command
pdf > func.asm    # redirect to a file
!ls -la           # run a shell command
. script.r2       # source an r2 script
#!pipe python3 solve.py     # run a python script bound to this session
```

## 3. Analysis

```
aa                # analyse symbols and entrypoints (fast)
aaa               # + calls and references (the default choice)
aaaa              # + aggressive experimental passes (slow)
aae               # ESIL emulation to resolve computed refs (jump tables, string pointers)
af                # analyse the function here
af @ 0x401136     # ... at an address
afl               # list functions (addr, size, name)
afll              # detailed listing (args, locals, cc, frame)
aflm              # names only, pipe-friendly
afi               # info about the current function
afn check_flag    # rename the current function
afv               # list function variables
afvn old new      # rename a variable
afvt buf "char *" # set a variable's type
afs int check(char *s, int n)    # set the function prototype
axt               # xrefs TO here (who calls/reads this?)
axt @ sym.imp.strcmp
axf               # xrefs FROM here
agf / agc / agC   # function graph / call graph / global call graph
agfd > g.dot      # export a dot graph
to /usr/include/stdio.h     # parse a C header into the type database
tl mystruct = 0x404060      # apply a type to an address
```

## 4. Seeking

```
s 0x401136 / s main / s sym.check    # seek to an address, symbol or flag
s+ 16 / s- 16                        # relative
sf.                                  # seek to the start of the current function
s                                    # print the current offset
s-                                   # undo (seek history);  s+ redo;  s* list
?v $$                                # evaluate: $$ here, $$$ function start,
                                     #   $F function size, $s file size, $B base
pd 10 @ $$+0x20                      # @ runs a command at a temporary seek
```

## 5. Printing and disassembling

```
pd 20             # disassemble 20 instructions
pdf               # disassemble the current function
pdr               # recursive disassembly (follows jumps)
pD 64             # disassemble 64 BYTES (not instructions)
pi 1              # one instruction, terse
px 64             # hexdump;  pxw / pxq / pxa for words / quads / annotated
ps / psz / psw    # string / zero-terminated / wide (UTF-16) string here
iz / izz          # strings in data sections / in the whole file
izz~http          # ... filtered
pf xxdz a b n s   # print with a struct format: x=u32 w=u16 q=u64 z=str b=byte *=ptr
pf.mystruct xxz a b name       # define a named format, then: pf.mystruct @ 0x404060
pc 64 / pcp 64 / pcj 64        # print bytes as C / python / JSON
pv4 @ 0x404060 / pv8           # print a value with the current endianness
p8 64 @ 0x404060               # raw bytes to stdout (for piping)
pdg / pdd         # decompile: r2ghidra / r2dec (plugins)
```

## 6. Searching

```
/ CTF{            # string search
/i flag           # case-insensitive
/x 4831c0         # hex bytes;  /x 48..c0 with wildcards
/a jmp rax        # assembly search
/R pop rdi        # ROP gadget search;  /R/ regex;  /Rl linear listing
/m                # magic/file signature scan
/r 0x404060       # references to an address
/v4 0xdeadbeef    # value search (/v8 for 64-bit)
e search.in=io.maps            # limit the region (io.section.exec, dbg.maps)
f~hit ; s hit0_0               # results become flags named hit0_*
```

## 7. Flags, comments and metadata

```
f myflag               # create a flag here;  f myflag 16 @ 0x404060 with a size
f                      # list;  f-myflag delete;  fr old new rename
fs ; fs strings ; fs * # flag spaces (namespaces), then `f` lists that space
CC this is the check   # comment here;  CC- deletes
Cd 4 / Cs / Cf 16 xxdz # define 4-byte data / a string / a formatted struct
C*                     # list all metadata
```

## 8. Writing and patching

```
oo+               # reopen in write mode (or start with r2 -w)
w hello           # write a string
wx 9090           # write hex bytes;  wx 4831c0c3 @ 0x401136
wa jmp 0x401200   # assemble and write an instruction
wao nop           # operate on the current instruction: nop it
wao ret0 / ret1   # make the function return 0 / 1
wao swap-jump     # invert the conditional jump  (also: wao jz, wao jnz)
wz 16             # write 16 zero bytes
wf patch.bin      # write a file's contents here
ww unicode        # write a wide string
w6d SGVsbG8=      # write decoded base64
e io.cache=true   # keep patches in memory until `wci` commits them
```

## 9. Debugging

```
ood [args]        # (re)open in debug mode
dc                # continue
dcu 0x401136      # continue until an address (dcu main)
dcc / dcr / dcs   # continue to the next call / return / syscall
db 0x401136       # breakpoint (db main);  db- removes;  db lists
dbc 0x401136 px 32     # run a command at a breakpoint
dbt               # backtrace
ds / ds 10 / dso  # step / step 10 / step over
dsu 0x401200      # step until an address;  dsf steps out of the frame
dr / dr rax / dr rax=1 # registers
drr               # registers with dereferenced values (telescope)
dm / dmm / dmi libc    # memory maps / modules / library symbols
dmh               # glibc heap chunks
wtf dump.bin 0x1000 @ 0x404000    # dump memory to a file
dk 9              # kill
```

## 10. Visual and panel modes

```
V                 # visual mode;  VV graph mode;  v panels mode
# inside visual mode:
#   p / P     rotate print modes        hjkl / arrows   move
#   Enter     follow a jump/call        u / U           undo / redo seek
#   x / X     xrefs to / from           g               goto
#   :cmd      run any r2 command        ;               add a comment
#   d         define (function/string/data)
#   n / N     rename                    A               assemble at the cursor
#   c         cursor mode, TAB selects  i               insert bytes
#   /         search                    q               back one level, ? help
```

## 11. Configuration

```
e                 # list config;  e~asm. to filter
e asm.syntax=intel
e asm.arch=x86 ; e asm.bits=64 ; e asm.cpu=cortex
e asm.pseudo=true      # pseudo-C instead of mnemonics
e asm.describe=true    # append a description to each instruction
e asm.bytes=true       # show raw bytes in the listing
e scr.color=3          # 0 none, 1 16, 2 256, 3 truecolor
e cfg.bigendian=true
e bin.relocs.apply=true    # resolve relocations statically (better PLT names)
e anal.timeout=30
eco / eco solarized        # themes
# ~/.radare2rc is just a list of r2 commands run at startup
Ps myproject / Po myproject / Pl      # save / load / list projects
```

## 12. Companion tools

```sh
# rabin2 - the readelf/objdump -h of r2 (works on ELF, PE, Mach-O alike)
rabin2 -I ./chall     # arch, bits, canary, nx, pic, stripped
rabin2 -S ./chall     # sections (-SS segments)
rabin2 -i ./chall     # imports (-E exports, -s symbols, -R relocs, -l libs, -H header)
rabin2 -z ./chall     # strings in data sections (-zz everywhere)

# rasm2 - assemble / disassemble one-liners (-L lists architectures)
rasm2 -a x86 -b 64 'mov rax, 60; syscall'
rasm2 -a x86 -b 64 -d '4831c0c3'
rasm2 -a arm -b 16 'push {r4,lr}'

# rax2 - the base converter
rax2 0x41          # 65
rax2 -s 4142       # hex -> ascii  ("AB")
rax2 -S AB         # ascii -> hex  ("4142")
rax2 -e 0xdeadbeef # endianness swap

# radiff2 / rafind2 / ragg2 / rarun2
radiff2 -x a.bin b.bin          # hex diff (-A -C function-level, -s similarity)
rafind2 -s 'CTF{' ./chall       # (-x for hex)
ragg2 -a x86 -b 64 -i exec -c cmd=/bin/sh    # build shellcode
ragg2 -P 200 -r                 # de Bruijn pattern
cat > p.rr2 <<'EOF'
#!/usr/bin/rarun2
program=./chall
stdin=./input.txt
setenv=LD_PRELOAD=./hook.so
EOF
r2 -d -r p.rr2 ./chall          # controlled execution profile
```

## 13. r2pipe scripting

```sh
pip install r2pipe
```

```python
#!/usr/bin/env python3
"""r2solve.py - analyse a binary, find the function that prints the success message,
and dump every constant it compares against.

    python3 r2solve.py ./chall [verdict_string]
    python3 r2solve.py ./chall --patch 0x401234 nop
"""
import json
import shutil
import sys

import r2pipe

PATCHES = {"nop": "wao nop", "invert": "wao swap-jump",
           "ret0": "wao ret0", "ret1": "wao ret1"}


def find_string(r2, needle):
    """The first string in the binary containing `needle` (case-insensitive)."""
    for entry in json.loads(r2.cmd("izzj") or "[]"):
        if needle.lower() in entry.get("string", "").lower():
            return entry
    return None


def owner_function(r2, addr):
    """The function that references `addr`, if any."""
    for xref in json.loads(r2.cmd("axtj %d" % addr) or "[]"):
        fcn = xref.get("fcn_addr")
        if fcn:
            info = json.loads(r2.cmd("afij %d" % fcn) or "[]")
            if info:
                return info[0]
    return None


def immediates_in(r2, fcn_addr):
    """Every small immediate used by a cmp/mov/xor/sub/add/test in a function."""
    out = []
    ops = json.loads(r2.cmd("pdfj @ %d" % fcn_addr) or "{}").get("ops", [])
    for op in ops:
        disasm = op.get("disasm", "")
        if not disasm.startswith(("cmp", "mov", "xor", "sub", "add", "test")):
            continue
        for token in disasm.replace(",", " ").split():
            if token.startswith("0x") and len(token) <= 6:
                try:
                    out.append((op["offset"], disasm, int(token, 16)))
                except ValueError:
                    pass
                break
    return out


def patch(path, addr, action):
    out = path + ".patched"
    shutil.copyfile(path, out)
    r2 = r2pipe.open(out, flags=["-w", "-2"])
    print("before:", r2.cmd("pd 1 @ %s" % addr).strip())
    r2.cmd("s %s" % addr)
    r2.cmd(PATCHES[action])
    print("after: ", r2.cmd("pd 1 @ %s" % addr).strip())
    r2.quit()
    print("[+] wrote", out)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    if "--patch" in sys.argv:
        idx = sys.argv.index("--patch")
        action = sys.argv[idx + 2]
        if action not in PATCHES:
            print("patch actions:", ", ".join(PATCHES))
            return 1
        patch(sys.argv[1], sys.argv[idx + 1], action)
        return 0

    needle = sys.argv[2] if len(sys.argv) > 2 else "Correct"
    r2 = r2pipe.open(sys.argv[1], flags=["-2"])
    r2.cmd("aaa")

    binfo = json.loads(r2.cmd("ij") or "{}").get("bin", {})
    print("[*] %s %s-bit pic=%s stripped=%s" % (binfo.get("arch"), binfo.get("bits"),
                                                binfo.get("pic"), binfo.get("stripped")))

    hit = find_string(r2, needle)
    if not hit:
        print("[-] no string containing %r; candidates:" % needle)
        print(r2.cmd("izz~flag"))
        r2.quit()
        return 1
    print("[+] %r at 0x%x" % (hit["string"], hit["vaddr"]))

    fcn = owner_function(r2, hit["vaddr"])
    if not fcn:
        print("[-] nothing references it - try `aaaa` or look for indirect refs")
        r2.quit()
        return 1
    print("[+] referenced from %s @ 0x%x (%d bytes)\n"
          % (fcn["name"], fcn["offset"], fcn["size"]))
    print(r2.cmd("pdf @ %d" % fcn["offset"]))

    candidate = bytearray()
    for addr, disasm, value in immediates_in(r2, fcn["offset"]):
        printable = chr(value) if 32 <= value < 127 else "."
        print("    0x%08x  %-28s 0x%02x %r" % (addr, disasm, value, printable))
        if 32 <= value < 127:
            candidate.append(value)
    if candidate:
        print("\n[+] printable immediates in order: %r" % candidate.decode())

    r2.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## 14. rizin and Cutter

`rizin` is a fork with a stabilised API; `Cutter` is its Qt GUI with the Ghidra decompiler
built in. Almost every command above works unchanged; only the tool names differ.

```sh
rizin ./chall                       # r2
rz-bin -I ./chall                   # rabin2
rz-asm -a x86 -b 64 -d '4831c0'     # rasm2
rz-diff -x a b                      # radiff2
rz-find -s 'CTF{' bin               # rafind2
cutter ./chall                      # GUI: graph + decompiler + an r2 console at the bottom
```

Use Cutter when you want the graph view and a decompiler; use r2 on the command line when
you want to script.

## 15. Quick recipes

```sh
# Where is the flag comparison?
r2 -q -A -c 'izz~flag' ./chall
# Which functions call strcmp?
r2 -q -A -c 'axt @ sym.imp.strcmp' ./chall
# All strings as JSON for further processing
r2 -q -A -c 'izzj' ./chall | python3 -m json.tool | head -50
# ROP gadgets
r2 -q -c '/R pop rdi' ./chall
# Function-level diff of two builds
radiff2 -A -C old.bin new.bin
# Patch a jump and verify in one line
r2 -w -q -c 's 0x401234; wao swap-jump; pd 1' ./chall
# Emulate a function with ESIL and read the result register
r2 -q -c 'aei; aeim; aeip; s 0x401136; aecu 0x401180; dr rax' ./chall
```

## References

- The radare2 book (`radare2/doc`), chapters on analysis, searching, writing and visual mode.
- `r2 -c '?*'` prints the entire command tree - the authoritative local reference.
- rizin documentation for the renamed tool set.
