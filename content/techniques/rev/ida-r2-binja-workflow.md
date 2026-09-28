---
title: "IDA, Binary Ninja, radare2 and Cutter - Cross-Tool Workflow"
category: rev
subcategory: disassemblers
type: technique
tags: [ida, idapython, binaryninja, hlil, mlil, radare2, r2pipe, cutter, rizin, rz-ghidra, ghidra, flirt, lumina, decompiler, xrefs, patching, rop, dataflow, visual-mode, shortcuts]
difficulty: medium
summary: "One translation table for the five main RE tools, plus each tool's killer feature with working idapython and r2pipe scripts."
when_to_use:
  - "You know one disassembler and a writeup is telling you to press keys in another"
  - "You need scripted analysis over many functions and want the right tool for it"
  - "Ghidra's decompiler is wrong and you want a second opinion from HLIL or Hex-Rays"
  - "You need FLIRT/Lumina to un-stripe a statically linked binary"
tools: [ida, idapython, binaryninja, radare2, r2pipe, cutter, rizin, ghidra]
related: [triage-unknown-binary, ghidra-workflow, dynamic-analysis-ltrace-ldpreload, binary-patching, shellcode-analysis, radare2-cheatsheet, ghidra-cheatsheet]
---

## TL;DR

Every RE tool does the same twelve things with different keys. Learn the table
once, then pick per *task*: IDA for signatures on stripped static binaries,
Binary Ninja for dataflow, radare2 for scripting and ROP, Cutter for a free GUI.

## Recognise it

- A writeup says "hit `Y` and set the type" - that is IDA, `Ctrl+L` in Ghidra.
- A stripped static 3 MB ELF, 4000 nameless functions - a FLIRT/Function-ID job.
- "Every `memcpy` whose size argument is a constant > 0x100" - a Binary Ninja
  MLIL/HLIL dataflow query, not a grep.
- "Give me all the `pop rdi; ret` gadgets" - `/R` in radare2, or ROPgadget.

## Command and shortcut translation table

| Task | IDA Pro | Binary Ninja | radare2 | Cutter | Ghidra |
| --- | --- | --- | --- | --- | --- |
| Rename symbol/var | `N` | `N` | `afn <new> <addr>` (func), `afvn <old> <new>` (var) | `N` | `L` |
| Xrefs to current | `X` | `X` | `axt <addr>` | `X` | `Ctrl+Shift+F` |
| Xrefs from current | `Ctrl+X` (or `X` panel) | right-click -> Xrefs From | `axf <addr>` | `X` panel | `Ctrl+Shift+F` (From tab) |
| Decompile | `F5` (Hex-Rays) | `Tab` / HLIL view | `pdg` (r2ghidra), `pdc` (built-in) | `Tab` / decompiler pane | `Ctrl+E` (auto) |
| Toggle graph / text | `Space` | `Space` | `VV` then `p` | `Space` | `Ctrl+Shift+G` |
| Define function | `P` (make procedure) | `P` / right-click Create Function | `af` (analyse function at) | `P` | `F` |
| Undefine | `U` | right-click Undefine | `af-` | `U` | `C` |
| Make code | `C` | `C` (make code) | `aa` region / `Cd` | `C` | `D` |
| Make data | `D` (cycles size) | `1`/`2`/`4`/`8` | `Cd 4`, `Cw`, `Cq` | `D` | `T` / `Ctrl+Shift+L` |
| Set type / prototype | `Y` | `Y` | `afs <signature>`, `tl <type>` | `Y` | `Ctrl+L` / Edit Function Signature |
| Create struct | Structures window (`Shift+F9`), `Ins` | Types view, `S` / `Create Struct from members` | `td "struct s { int a; };"` | Types panel | Data Type Manager -> New Structure |
| Patch bytes | `Edit -> Patch Program -> Change byte` | `Ctrl+Shift+A` Assemble / Patch | `wx <hex>`, `wa <asm>`, `wao nop` | `Edit -> Write` / Hexdump | `Ctrl+Shift+G` -> Patch Instruction |
| Apply patch to file | `Edit -> Patch -> Apply to input file` | `File -> Save As` (patched) | open with `-w`, writes live | `File -> Save` | `File -> Export -> Original File` |
| String window | `Shift+F12` | Strings view (`Ctrl+3` layout dep.) | `iz` (data sections), `izz` (whole file) | Strings panel | `Window -> Defined Strings` |
| Comment | `:` (repeatable `;`) | `;` | `CC <text> @ <addr>` | `;` | `;` (EOL), `Ctrl+;` (pre) |
| Jump to address | `G` | `G` | `s <addr>` (seek) | `G` | `G` |
| Jump to name | `Ctrl+P` (functions) | `Ctrl+P` (command palette), `G` name | `s sym.main` | `Ctrl+P` | `G` + name |
| Search bytes | `Alt+B` | `Ctrl+F` (bytes/hex) | `/x 90909090` | `Ctrl+F` | `Search -> Memory` |
| Search string | `Alt+T` | `Ctrl+F` (text) | `/ password` | `Ctrl+F` | `Search -> Memory` (String) |
| Search assembly | `Alt+B` on encoded bytes | `Ctrl+F` -> asm | `/ad jmp rax` | Search panel | `Search -> Instruction Pattern` |
| Back / forward | `Esc` / `Ctrl+Enter` | `Alt+Left` / `Alt+Right` | `u` / `U` | `Esc` | `Alt+Left` / `Alt+Right` |
| Function list | `Shift+F3` / left panel | Symbols sidebar | `afl` | Functions panel | Symbol Tree -> Functions |
| Segments / sections | `Ctrl+S` | `Ctrl+S` layout dep. | `iS` | Sections panel | `Window -> Memory Map` |
| Imports | `Ctrl+S` -> imports, or Imports tab | Symbols -> Imports | `ii` | Imports panel | Symbol Tree -> Imports |
| Hex view | `F2`/Hex View-A | Hex view | `px 64`, `pxw`, `pxq` | Hexdump panel | `Window -> Bytes` |
| Set base address | `Edit -> Segments -> Rebase` | `Options -> base` on load | `-B 0x400000` at load, `omb` | Rebase dialog | Memory Map -> image base |
| Run script | `Alt+F7` (file), `Shift+F2` (snippet) | `Ctrl+backtick` console, Plugins menu | `#!pipe`, `. script.r2`, `r2pipe` | Python console | Script Manager |
| Debugger start | `F9` | `F9` (debugger view) | `r2 -d ./chall`, then `dc` | `F9` | Debugger (11.x) / gdb+ret-sync |
| Breakpoint | `F2` | `F2` | `db <addr>` | `F2` | `F2` |
| Step into / over | `F7` / `F8` | `F7` / `F8` | `ds` / `dso` | `F7` / `F8` | `F8` / `F10` |

Two traps: **`C` is opposite** (IDA/Cutter `C` makes code, Ghidra `C` *clears*
it - use `D`), and **`X` vs `Ctrl+X`** (IDA splits xrefs-to from xrefs-from,
Ghidra shows both, r2 has `axt`/`axf`).

## IDA Pro - killer feature: FLIRT and Lumina

A statically linked stripped binary is 95% libc. FLIRT pattern-matches known
library bodies and renames them, leaving only the author's code to read. Lumina
is the cloud version: metadata keyed by a hash of the function's normalised
bytes, so functions other people named show up named for you.

Apply one with `View -> Open subviews -> Signatures` (`Shift+F5`, `Ins`), or in
batch: `ida -A -Slibc.idc ./chall`. Sets live in `<IDA>/sig/pc/*.sig`
(`libc_gcc_*.sig`, `vc32rtf.sig`, `vc64rtf.sig`).

On a stripped static ELF: (1) `Shift+F5` -> `Ins` -> pick the `libc_gcc_*` sets
and watch the unnamed count collapse; (2) if nothing matches, build your own from
the matching `libc.a` with FLAIR - `pelf libc.a libc.pat`, `sigmake libc.pat
libc.sig`, deleting the leading comment lines of the `.exc` collision file to
accept them all; (3) `File -> Lumina -> Pull all metadata`; (4) only then read -
the remaining `sub_*` are the challenge.

Ghidra's equivalent is **Function ID** (`Tools -> Function ID`, `.fidb`); Binary
Ninja's is **Signature Libraries** (`Analysis -> Signature Libraries`, `.sig`).

```python
"""IDAPython (7.4+ / 8.x / 9): find calls whose arguments are constants -
the flag length, XOR key, checksum and memcpy size are almost always
immediates pushed just before the call - comment each site and report.
Run in IDA: Alt+F7.  Headless: idat64 -A -S"ida_const_args.py" ./chall
"""
import idaapi, idautils, idc, ida_funcs, ida_bytes

TARGETS = ("memcmp", "strncmp", "strcmp", "memcpy", "strncpy", "malloc",
           "calloc", "read", "write", "srand", "ptrace", "mprotect")
LOOKBACK = 12                  # instructions to scan back for immediates
def callee_name(ea):           # undecorated name called at `ea`, or None
    target = idc.get_operand_value(ea, 0)
    if target in (idc.BADADDR, -1):
        return None
    name = idc.get_func_name(target) or idc.get_name(target)
    # Strip IDA's import decorations: .memcpy, _memcpy, __imp_memcpy
    return name.lstrip("._").replace("imp_", "") if name else None
def immediates_before(ea, limit=LOOKBACK):   # (addr, imm) before the call
    found, cur = [], ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        # stop at BADADDR and do not cross a basic-block boundary
        if cur == idc.BADADDR or idc.print_insn_mnem(cur) in ("call", "jmp", "ret"):
            break
        for op in range(3):
            if idc.get_operand_type(cur, op) == idaapi.o_imm:
                found.append((cur, idc.get_operand_value(cur, op)))
    return found
def scan():
    hits = 0
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        for ea in idautils.Heads(func.start_ea, func.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)) or \
                    idc.print_insn_mnem(ea) != "call":
                continue
            name = callee_name(ea)
            consts = immediates_before(ea) if name in TARGETS else []
            if not consts:
                continue
            pretty = ", ".join("0x%x" % v for _a, v in consts[:4])
            print("0x%08x %-24s %s(...) consts: %s" % (ea, idc.get_func_name(func_ea), name, pretty))
            idc.set_cmt(ea, "const args: %s" % pretty, 0)
            hits += 1
    print("[+] annotated %d call sites" % hits)
if __name__ == "__main__":
    idaapi.auto_wait()         # let auto-analysis settle before walking
    scan()
```

```python
# Snippets: paste into the Output window input line (Shift+F2).
import idautils, idc, ida_bytes

# 1. Every string with its xref count.
for s in idautils.Strings():
    print("0x%x  refs=%d  %s" % (s.ea, len(list(idautils.DataRefsTo(s.ea))), s))

# 2. jz -> jmp: 0x74 (jz rel8) becomes 0xEB (jmp rel8).
TARGET = 0x004011a7
if ida_bytes.get_byte(TARGET) == 0x74:
    ida_bytes.patch_byte(TARGET, 0xEB)

# 3. NOP out a call (5 bytes for an x86 near call).
for off in range(5):
    ida_bytes.patch_byte(0x004011c0 + off, 0x90)

# 4. Read a decrypted buffer out of the IDB after a debugger run.
print(ida_bytes.get_bytes(0x00404060, 0x40).hex())

# 5. Rename every sub_* that calls ptrace so it stands out.
for func_ea in idautils.Functions():
    for ref in idautils.CodeRefsFrom(func_ea, 1):
        if idc.get_name(ref) in ("ptrace", ".ptrace", "_ptrace"):
            idc.set_name(func_ea, "antidbg_%x" % func_ea, idc.SN_CHECK)
```

## Binary Ninja - killer feature: HLIL and dataflow over MLIL

Binary Ninja exposes its ILs as a queryable API: LLIL is architecture-normalised
instructions, MLIL adds variables and SSA, HLIL is structured pseudo-C. Every
MLIL expression carries a value range (`.possible_values`), so you can ask "what
values can this argument take?" without running anything: `memcmp(user, exp,
0x20)` gives you the flag length before you read an instruction, even when the
constant arrives via three register moves and a spill, because MLIL SSA
propagated it already.

```python
"""Binary Ninja: report every call with constant arguments, flag the
memcmp-family length (usually the flag length), optionally dump one HLIL.
Headless: python3 bn_const_calls.py ./chall [funcname]; in the GUI, exec()
this file in the Python console. Needs Personal/Commercial: Free has no API.
"""
import sys

import binaryninja
from binaryninja import RegisterValueType

INTERESTING = {                # call name -> index of the size/key argument
               "memcmp": 2, "strncmp": 2, "memcpy": 2, "strncpy": 2,
               "malloc": 0, "read": 2, "recv": 2, "srand": 0, "mprotect": 2}
def const_value(param):        # int if the MLIL param is a known constant
    val = getattr(param, "possible_values", None)
    if val is not None and val.type in (RegisterValueType.ConstantValue,
                                        RegisterValueType.ConstantPointerValue):
        return val.value
    return None
def callee_symbol(bv, call_expr):    # target symbol name of an MLIL call
    addr = getattr(call_expr.dest, "constant", None)
    if addr is None:
        return None
    sym = bv.get_symbol_at(addr)
    func = bv.get_function_at(addr)
    return sym.short_name if sym else (func.name if func else None)
def walk(bv):
    total = 0
    for func in bv.functions:
        for block in func.mlil or []:
            for insn in block:
                if insn.operation.name not in ("MLIL_CALL", "MLIL_TAILCALL"):
                    continue
                short = (callee_symbol(bv, insn) or "").lstrip("._")
                if short not in INTERESTING:
                    continue
                params = list(insn.params)
                known = [(i, const_value(p)) for i, p in enumerate(params)]
                known = [(i, v) for i, v in known if v is not None]
                if not known:
                    continue
                print("0x%08x  %-28s %s(%s)" % (insn.address, func.name, short,
                      ", ".join("arg%d=0x%x" % (i, v) for i, v in known)))
                idx = INTERESTING[short]
                size = const_value(params[idx]) if idx < len(params) else None
                if size is not None and short in ("memcmp", "strncmp"):
                    print("     ^ comparison length %d = flag length" % size)
                total += 1
    print("[+] %d constant-argument call sites" % total)
def dump_hlil(bv, name):       # HLIL (pseudo-C) of every function so named
    for func in bv.get_functions_by_name(name):
        print("/* ---- %s @ 0x%x ---- */" % (func.name, func.start))
        for line in func.hlil.root.lines:
            print(str(line))
if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "./chall"
    with binaryninja.load(path) as bv:
        bv.update_analysis_and_wait()   # mandatory before reading MLIL
        print("[*] %s: %d funcs, arch=%s" % (path, len(bv.functions),
                                             bv.arch.name))
        walk(bv)
        if len(sys.argv) > 2:
            dump_hlil(bv, sys.argv[2])
```

Other levers: `Tab` cycles Disassembly -> LLIL -> MLIL -> HLIL (read HLIL, debug
in MLIL); right-click a variable -> **Split/Merge Variables** when stack slots
were over- or under-merged; **Patch** (`Ctrl+Shift+A` assemble, or right-click ->
Patch -> Invert Branch / Never Branch / Always Branch / NOP) then `File -> Save
As` - Invert Branch is the fastest crackme patch in any tool;
`bv.get_code_refs(addr)`, `func.get_llil_at(addr)` for scripted xrefs.

## radare2 - killer feature: scriptability, ROP search and visual mode

r2 is a shell: every command prints text and takes a `j` suffix for JSON (hence
`r2pipe`). Letters nest: `a`nalyse `p`rint `s`eek `w`rite `d`ebug `i`nfo `/`search.

```sh
r2 -A ./chall                      # open + analyse, read-only
r2 -w ./chall                      # writable: wx/wa patch the file on disk
r2 -d ./chall                      # debugger target
r2 -qc 'aaa; afl' ./chall          # one-shot command, quit (-q), no banner
r2 -qc 'aa; afl~main' ./chall      # aa = basic; aaaa = deep (esil), slow+noisy
afl~check                          # list functions, `~` is the internal grep
pdf @ sym.main                     # print disassembly of a function
pdg @ sym.check_flag               # decompile (r2pm -ci r2ghidra)
iz                                 # strings in data sections
izz~flag                           # ...in the whole file, grepped
axt sym.imp.strcmp                 # xrefs to an address or symbol
s 0x004040a0; px 64                # seek, then hexdump
/x 4889e5                          # search bytes
/ad jmp rax                        # search an assembly pattern
/ FLAG                             # search a string
/R pop rdi                         # ROP gadget search (built-in engine)
/R/ pop r[a-z]+;.*ret              # regex form; /Rl "pop rdi; ret" = list form
wa nop @ 0x004011a7                # assemble in place (needs -w)
wx 9090 @ 0x004011a7               # write raw hex
wao nop @ 0x004011a7               # nop exactly the instruction there
wao jinf @ 0x004011a7              # turn it into an infinite loop
wao ret0 @ sym.anti_debug          # make the function `xor eax,eax; ret`
aei; aeim; aeip; 20aes; aer        # ESIL: init, map, set pc, step 20, regs
```

Visual mode is where r2 becomes usable interactively:

```sh
# V = visual (p/P cycle panels), VV = visual graph, V! = panels (IDE-like)
#   hjkl / arrows  move        :cmd  run any r2 command
#   g  seek to     q  leave    x  xrefs to    X  xrefs from
#   d  define (function/data/string submenu)
#   c  cursor mode, then Tab/insert to edit bytes
#   ;  add comment             p / P  rotate print modes
```

```python
#!/usr/bin/env python3
"""r2pipe: analyse a binary, find the function owning the success/failure
strings, dump the immediates inside it - the scripted version of
  iz | grep Correct ; axt <addr> ; pdf @ <func>
Usage: python3 r2_findcheck.py ./chall  (pip install r2pipe; radare2 on PATH)
"""
import json, sys

import r2pipe

GOOD_WORDS = ("correct", "well done", "flag", "ctf{", "success", "nice")
BAD_WORDS = ("wrong", "nope", "incorrect", "try again", "denied")
def cmdj(r2, cmd):             # r2 command -> parsed JSON, [] if unusable
    raw = r2.cmd(cmd)
    try:
        return json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError:
        return []
def verdict_strings(r2):       # (kind, vaddr, text) for verdict-ish strings
    out = []
    for e in cmdj(r2, "izzj"):
        low = e.get("string", "").lower()
        kind = ("GOOD" if any(w in low for w in GOOD_WORDS) else
                "BAD" if any(w in low for w in BAD_WORDS) else None)
        if kind:
            out.append((kind, e.get("vaddr", 0), e.get("string", "")))
    return out
def dump_constants(r2, func_name):   # the check's guts: cmp/test/xor imms
    print("--- constants in %s ---" % func_name)
    ops = cmdj(r2, "pdfj @ %s" % func_name)
    for op in (ops.get("ops", []) if isinstance(ops, dict) else []):
        disasm = op.get("disasm", "")
        if disasm.split(" ")[0] not in ("cmp", "test", "xor", "sub", "add",
                                        "mov", "movzx"):
            continue
        if "0x" not in disasm or ("[" in disasm and "rip" in disasm):
            continue          # skip register-only and rip-relative noise
        print("    0x%08x  %s" % (op.get("offset", 0), disasm))
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chall"
    r2 = r2pipe.open(path, flags=["-2"])     # -2 silences r2's stderr
    try:
        r2.cmd("aaa")
        info = cmdj(r2, "ij")
        b = info.get("bin", {}) if isinstance(info, dict) else {}
        print("[*] %s arch=%s bits=%s pic=%s stripped=%s" % (path, b.get("arch"),
              b.get("bits"), b.get("pic"), b.get("stripped")))
        targets = set()
        for kind, vaddr, text in verdict_strings(r2):
            owners = {r.get("fcn_name") for r in cmdj(r2, "axtj @ 0x%x" % vaddr)
                      if r.get("fcn_name")}
            print("[%s] 0x%08x %-40r <- %s" % (kind, vaddr, text[:40], owners))
            targets |= owners
        if not targets:      # fall back to the biggest non-library function
            funcs = [f for f in cmdj(r2, "aflj")
                     if not f.get("name", "").startswith(("sym.imp", "sub."))]
            funcs.sort(key=lambda f: f.get("size", 0), reverse=True)
            targets = {f["name"] for f in funcs[:1]}
        for name in sorted(targets):
            dump_constants(r2, name)
        print("[+] next: r2 -A %s ; pdg @ %s" % (path, sorted(targets)[0] if targets else "sym.main"))
    finally:
        r2.quit()
if __name__ == "__main__":
    main()
```

## Cutter and rizin

Cutter is the Qt GUI over **rizin** (the maintained radare2 fork): free, and the
fastest way to get a graph view, a debugger and a Ghidra decompiler in one app.

```sh
rz-pm -ci rz-ghidra    # decompiler backend for rizin (Cutter bundles it)
pdg @ main             # Ghidra decompilation - same engine, no JVM app
pdgo @ main            # ...annotated with offsets;  pdgs = the SLEIGH p-code
```

- Debug: `Debug -> Start debugging`, then the Registers/Stack/Backtrace docks,
  `F2` breakpoints, `F7`/`F8` stepping; attach and gdbserver both work.
- **Graph view** (`Space`) is the best free CFG view after IDA's.
- Plugins are Python in `~/.local/share/rizin/cutter/plugins/python/`, using the
  `cutter` module plus `CutterCore` passthrough, so any rizin command works.
- rizin syntax is r2 syntax with a few renames (`iz`, `axt`, `pdf`, `afl` are
  identical); scripts use `rzpipe`, same API as `r2pipe`.

## Which tool for which job

| Situation | Reach for |
| --- | --- |
| Stripped static ELF, thousands of functions | IDA + FLIRT, or Ghidra + Function ID |
| "Which calls have a constant size argument?" | Binary Ninja MLIL `possible_values` |
| Batch decompile 50 binaries | Ghidra `analyzeHeadless` |
| Need ROP gadgets / byte patching from a script | radare2 `/R` + `wx`, or ROPgadget |
| Obfuscated control flow, want emulation | radare2 ESIL (`aei`/`aes`), or Unicorn |
| Free GUI with debugger and good decompiler | Cutter |
| Best-quality C++ / RTTI recovery | IDA (with Hex-Rays), Ghidra's RTTI analyzer second |
| Second opinion on a bad decompilation | run Hex-Rays and Ghidra on the same function and diff |

## Variants & pitfalls

- **Decompilers disagree and both can be wrong**: if the pseudo-C makes no sense
  read the disassembly - a wrong calling convention gives confident nonsense.
- **IDA batch mode**: `idat64 -A -S"script.py" target` (`-A` autonomous, `-c`
  deletes the old IDB); `idat`, the text-mode binary, is the scripting one.
- **`aaaa` is not "more a's is better"**: its experimental analysis invents
  garbage functions on obfuscated binaries; default to `aaa`.
- **r2 seek is global state**: prefer `cmd("pdf @ sym.x")` over `cmd("s sym.x")`
  plus `cmd("pdf")`, so a failure does not leave you reading elsewhere.
- **r2/rizin API drift**: JSON keys change between versions, so always `.get()`.
- **Binary Ninja**: `binaryninja.load()` is the modern API (older scripts use
  `BinaryViewType.get_view_of_file()`); always `update_analysis_and_wait()`.
- **Patching in radare2 needs `-w`**; IDA patches live in the IDB until
  `Edit -> Patch program -> Apply patches to input file`.
- **Shortcut collisions**: `Ctrl+Shift+A` (BN assemble) and `F9` are commonly
  stolen by tiling window managers.

## Tools

- **IDA Pro / Free** - Hex-Rays (Pro), FLIRT, Lumina, IDAPython; IDA 9 Free has
  the x86-64 decompiler, older Free builds have no decompiler or scripting.
- **FLAIR** (`pelf`, `pcf`, `sigmake`, `zipsig`) - build your own FLIRT sigs.
- **Binary Ninja** - ILs, Python API, sig libraries; **radare2** - `r2pm`
  (`r2ghidra`, `r2dec`, `r2frida`); **rizin/Cutter** - `rz-pm`, `rz-ghidra`, `rzpipe`.
- **ROPgadget**, **ropper** - gadget finders; **ret-sync** - sync IDA/Ghidra/BN
  with a live debugger; **BinDiff**, **Diaphora** - binary diffing across builds.

## References

- Hex-Rays IDA docs and the IDAPython API reference (`ida_bytes`, `ida_funcs`,
  `idautils`, `idc`); FLAIR/FLIRT docs for `pelf` and `sigmake`.
- Binary Ninja API documentation (api.binary.ninja) - `BinaryView`, `Function`,
  `MediumLevelILInstruction.possible_values`, `RegisterValueType`.
- radare2 book (book.rada.re) - command hierarchy, ESIL, visual mode, ROP;
  rizin and Cutter docs (rizin.re, cutter.re), including `rz-ghidra`.
