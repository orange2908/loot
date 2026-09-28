---
title: "Go Binaries - pclntab, String Slicing, Register ABI"
category: rev
subcategory: golang
type: technique
tags: [golang, go, gopclntab, pclntab, goresym, stripped-binaries, morestack, buildinfo, goroutines, newproc, channels, itab, interfaces, register-abi, slicebytetostring, ghidra, ida, radare2, string-recovery, delve]
difficulty: medium
summary: "Rebuild function names from .gopclntab in a stripped Go binary, slice the run-on string blob into real constants, and read the 1.17+ register ABI."
when_to_use:
  - "`file` says 'Go BuildID' or a hello-world-sized program is 2-15 MB"
  - "`strings` shows `runtime.`, `go:buildinfo`, `go1.2x.y`, or one enormous unbroken blob"
  - "The decompiler finds no `main` but thousands of `runtime_*` / `morestack` calls"
  - "A stripped ELF/PE still carries `.gopclntab` or `.note.go.buildid`"
  - "Every comparison looks like a length test plus a memcmp instead of `strcmp`"
tools: [ghidra, ida, radare2, goresym, delve, gdb, python]
related: [triage-unknown-binary, ghidra-workflow, ida-r2-binja-workflow, rust-binaries, cpp-vtables-stl, dynamic-analysis-ltrace-ldpreload]
---

## TL;DR

Go statically links its whole runtime, so binaries are huge. Stripping removes `.symtab` but
almost never `.gopclntab` - the runtime needs it for stack traces - so every function name is
recoverable. Second trap: Go strings are `(ptr, len)` with no NUL, so plain `strings` prints
`.rodata` as one run-on blob and any "flag" read straight out of it is wrong.

## Recognise it

| Signal | Check |
|---|---|
| Toolchain string | `strings -a ./bin \| grep -m1 'go1\.'` -> `go1.21.5` |
| Sections | `readelf -S -W ./bin \| grep -E 'gopclntab\|buildinfo\|go.buildid'` |
| Runtime symbols | `nm ./bin \| grep -c ' t runtime\.'` -> hundreds |
| Universal prologue | `cmp rsp,[r14+0x10]` (1.17+) or `[fs:0xfffffff8]`, tail `call runtime.morestack_noctxt` |

```sh
# Fastest identification; works stripped or not, no disassembler needed
go version -m ./bin      # module path, toolchain version, build flags, dependency list
file ./bin               # "Go BuildID=..." present unless -ldflags="-w -s"
readelf --syms ./bin | wc -l    # 0 or ~4 on a stripped build
```

## How it works

### `.gopclntab`

The pc-line table maps PCs to function metadata. The header magic gives you the layout:

| Magic (LE u32) | Go | functab entry |
|---|---|---|
| `0xfffffffb` | 1.2-1.15 | `(entry uintptr, funcoff uintptr)`, name offsets relative to table start |
| `0xfffffffa` | 1.16-1.17 | same entries, header gains explicit sub-table offsets |
| `0xfffffff0` | 1.18-1.19 | `(entryoff u32, funcoff u32)`, real address = `textStart + entryoff` |
| `0xfffffff1` | 1.20+ | identical to 1.18 |

After the magic: `pad[2], minLC u8, ptrSize u8`, `nfunc`, `nfiles`, (1.18+) `textStart`, then
`funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset` - each `ptrSize` wide and
relative to the table start. Each functab entry points at a `_func`, whose `nameoff` (`i32` at
`+4` on 1.18+, at `+ptrSize` before) indexes a NUL-terminated name in the funcname blob.

### Strings are fat pointers

```go
s := "flagctf"
```

```asm
lea    rax, [rip+0x8a2f1]   ; -> "flagctf{...}NEXTCONSTANTstartsimmediately"
mov    ebx, 7               ; length, in the second ABI register
call   main.check
```

`.rodata` holds every string body concatenated with no terminators. To recover a real constant
you must find its `(ptr, len)` construction: a static two-word header in `.rodata`/`.data.rel.ro`,
or the `lea` + length-immediate pair in `.text`.

### Types and interfaces

* `runtime._type` records live in `.rodata` (`size, ptrdata, hash, tflag, align, kind, equal,
  gcdata, str, ptrToThis`); GolangAnalyzerExtension turns them back into named Ghidra structs.
* An interface value is two words: `(itab*, data*)`, or `(_type*, data*)` for `any`.
* An `itab` is `{inter*, _type*, hash u32, _ u32, fun[0] uintptr}`, so the first method sits at
  `+0x18`: an interface dispatch reads `mov rax,[rdi]; call qword [rax+0x18]`.
* `runtime.convT64` / `convTstring` / `convTslice` mark where a concrete value is boxed into an
  interface - nearly always a `fmt.Print*` argument.

### Calling convention

Pre-1.17 everything is on the stack: arguments at `[rsp+8]`, `[rsp+0x10]`, ..., return values
immediately after them. 1.17+ uses `ABIInternal`, a register ABI:

```text
integer/pointer args, in order:  RAX RBX RCX RDI RSI R8 R9 R10 R11
floats: X0..X14      R14 = current g      R12/R13 = scratch      RDX = closure context
```

Returns come back in the *same* registers, so `func f() (int, error)` yields
`RAX=int, RBX=error.itab, RCX=error.data`. Ghidra's default convention shows garbage: apply the
GolangAnalyzerExtension convention, or *Edit Function Signature* -> custom storage and place the
parameters in RAX/RBX/RCX by hand. Multi-value returns are why a trivial Go function appears to
clobber five registers before `ret`.

### Runtime calls worth breakpointing

| Call | Meaning |
|---|---|
| `runtime.newproc` | spawn goroutine; the `*funcval` argument's **first word is the entry PC** |
| `runtime.chansend1` / `chanrecv1` | `ch <- v` / `v := <-ch`; arg1 `hchan*`, arg2 element pointer |
| `runtime.deferproc` / `deferreturn` | `defer`; the deferred func pointer is the argument |
| `runtime.gopanic` / `gorecover` | `panic`/`recover`, often used as obfuscated control flow |
| `runtime.slicebytetostring` | `string(b)` - whatever was just built is the plaintext |
| `runtime.memequal` | the actual flag comparison; both operands are in registers |
| `runtime.mapaccess1_faststr` | `m[key]`; key ptr + len passed directly |

### Finding `main.main`

`main.main` is a literal name in pclntab, so the script below finds it even when stripped.
Otherwise `runtime.main` calls it - the second indirect call after `runtime.init`. In radare2:
`aa; afl~main.main; s sym.main.main; pdf`. Global constants are built in `main.init`, not
`main.main`, so that is where an encrypted flag table gets decoded.

## Workflow

1. **Version-pin**: `go version -m ./bin` tells you which pclntab layout applies.
2. **Recover symbols**: un-stripped -> `nm ./bin | grep ' t main\.'`. Stripped ->
   ```sh
   # GoReSym emits JSON with every recovered user + std function
   GoReSym -t -d -p ./bin > syms.json
   jq -r '.UserFunctions[] | "\(.Start) \(.FullName)"' syms.json
   ```
   or run `go_pclntab.py` below (no dependencies).
3. **Apply the names**: Ghidra + GolangAnalyzerExtension (tick "Golang Analyzer" in auto-analyze),
   IDA + `golang_loader_assist.py` (Alt+F7), or the `--ghidra` rename script emitted below.
4. **Rebuild strings** with `go_strings.py`, then grep for `flag`, `wrong`, `Correct`, `{`.
5. **Break on runtime helpers, not user code**:
   ```sh
   # every string comparison; one operand is the expected flag
   gdb -q ./bin -ex 'break runtime.memequal' -ex run -ex 'x/s $rdi' -ex 'x/s $rsi'
   ```
6. **Delve** if DWARF survived: `dlv exec ./bin`, then `break main.main`, `continue`, `locals`.

## Code

### Recover function names from `.gopclntab`

```python
#!/usr/bin/env python3
"""List function addresses + names from a (possibly stripped) Go ELF via .gopclntab.

Handles magics 0xfffffffb (1.2), 0xfffffffa (1.16), 0xfffffff0 (1.18), 0xfffffff1 (1.20).
Usage: python3 go_pclntab.py ./bin [--ghidra out.py]
"""
import re
import struct
import sys

MAGICS = {0xFFFFFFFB: "go1.2", 0xFFFFFFFA: "go1.16",
          0xFFFFFFF0: "go1.18", 0xFFFFFFF1: "go1.20"}


def elf_sections(blob):
    """Minimal ELF32/64 section walk -> {name: (vaddr, file_off, size)}."""
    if blob[:4] != b"\x7fELF":
        return {}
    is64 = blob[4] == 2
    end = "<" if blob[5] == 1 else ">"
    if is64:
        shoff, = struct.unpack_from(end + "Q", blob, 0x28)
        entsz, num, stridx = struct.unpack_from(end + "HHH", blob, 0x3A)
        addr_o, off_o, size_o = 0x10, 0x18, 0x20
    else:
        shoff, = struct.unpack_from(end + "I", blob, 0x20)
        entsz, num, stridx = struct.unpack_from(end + "HHH", blob, 0x2E)
        addr_o, off_o, size_o = 0x0C, 0x10, 0x14
    q = end + ("Q" if is64 else "I")
    raw = []
    for i in range(num):
        b = shoff + i * entsz
        raw.append((struct.unpack_from(end + "I", blob, b)[0],
                    struct.unpack_from(q, blob, b + addr_o)[0],
                    struct.unpack_from(q, blob, b + off_o)[0],
                    struct.unpack_from(q, blob, b + size_o)[0]))
    stro = raw[stridx][2]
    secs = {}
    for nameoff, addr, off, size in raw:
        e = blob.index(b"\x00", stro + nameoff)
        secs[blob[stro + nameoff:e].decode("utf-8", "replace")] = (addr, off, size)
    return secs


def find_pclntab(blob, secs):
    """Named section first; otherwise brute-force the magic on 16-byte boundaries (PE/stripped)."""
    for name in (".gopclntab", "__gopclntab", ".data.rel.ro.gopclntab"):
        if name in secs:
            return secs[name][1]
    for off in range(0, len(blob) - 16, 16):
        magic, = struct.unpack_from("<I", blob, off)
        if (magic in MAGICS and blob[off + 4] == 0 and blob[off + 5] == 0
                and blob[off + 6] in (1, 2, 4) and blob[off + 7] in (4, 8)):
            return off
    return None


def parse(blob, base):
    """-> (version, ptrsize, [(addr, name), ...]) for the table at file offset `base`."""
    magic, = struct.unpack_from("<I", blob, base)
    ver = MAGICS[magic]
    ptrsize = blob[base + 7]
    q = "<Q" if ptrsize == 8 else "<I"

    def rd(o):
        return struct.unpack_from(q, blob, o)[0]

    p = base + 8
    nfunc = rd(p)
    p += ptrsize
    text_start = 0
    if ver == "go1.2":
        funcname_base = funcdata_base = base             # name offsets relative to table start
        functab = p                                      # entries follow nfunc directly
    else:
        p += ptrsize                                     # nfiles
        if ver in ("go1.18", "go1.20"):
            text_start = rd(p)
            p += ptrsize
        funcname_base = base + rd(p)
        p += ptrsize * 4                                 # funcname + cu + filetab + pctab
        functab = funcdata_base = base + rd(p)           # pclnOffset

    wide = ver in ("go1.18", "go1.20")
    ent = 4 if wide else ptrsize
    out = []
    for i in range(nfunc):
        o = functab + i * 2 * ent
        if o + 2 * ent > len(blob):
            break
        if wide:
            entryoff, funcoff = struct.unpack_from("<II", blob, o)
            addr = text_start + entryoff
            noff_at = funcdata_base + funcoff + 4        # _func{entryoff u32, nameoff i32}
        else:
            addr, funcoff = rd(o), rd(o + ptrsize)
            noff_at = funcdata_base + funcoff + ptrsize  # _func{entry uintptr, nameoff i32}
        if not 0 <= noff_at < len(blob) - 4:
            continue
        sp = funcname_base + struct.unpack_from("<i", blob, noff_at)[0]
        if not 0 <= sp < len(blob):
            continue
        e = blob.find(b"\x00", sp)
        if e < 0 or e - sp > 512:
            continue
        name = blob[sp:e].decode("utf-8", "replace")
        if name.isprintable():
            out.append((addr, name))
    return ver, ptrsize, out


def main(argv):
    path = argv[1] if len(argv) > 1 else "./bin"
    blob = open(path, "rb").read()
    base = find_pclntab(blob, elf_sections(blob))
    if base is None:
        print("no pclntab magic found (packed? garbled? non-Go?)")
        return 1
    ver, ptrsize, funcs = parse(blob, base)
    print("# pclntab @0x%x layout=%s ptrsize=%d funcs=%d" % (base, ver, ptrsize, len(funcs)))
    user = [f for f in funcs if re.match(r"^(main|ctf|github\.com|gitlab\.com)", f[1])]
    for addr, name in (user or funcs):
        print("0x%08x %s" % (addr, name))
    if "--ghidra" in argv:
        dest = argv[argv.index("--ghidra") + 1]
        with open(dest, "w") as fh:                      # Jython: Ghidra Script Manager -> Run
            fh.write("from ghidra.program.model.symbol import SourceType\n")
            for addr, name in funcs:
                fh.write("createLabel(toAddr(0x%x), %r, True, SourceType.USER_DEFINED)\n"
                         % (addr, name))
        print("# wrote %s (%d labels)" % (dest, len(funcs)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

### Slice real string constants out of the blob

```python
#!/usr/bin/env python3
"""Recover Go string constants by finding (ptr,len) pairs that point into .rodata.

Scans two sources:
  static headers in data sections  -> [ptr uintptr][len uintptr]
  code in .text                    -> lea reg,[rip+d32] followed by a length immediate
Usage: python3 go_strings.py ./bin [minlen]
"""
import re
import struct
import sys

from go_pclntab import elf_sections            # reuse the section walker from the script above

# REX.W 8d /r, mod=00 rm=101 -> lea r64, [rip+disp32]
LEA_RIP = re.compile(rb"\x48\x8d([\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(....)", re.S)


def imm_lengths(win):
    """Length immediates the compiler emits right after loading the string pointer."""
    out, i = [], 0
    while i < len(win) - 4:
        b = win[i]
        if b in (0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF):                 # mov r32, imm32
            out.append(struct.unpack_from("<I", win, i + 1)[0])
            i += 5
        elif b == 0x48 and win[i + 1] == 0xC7 and 0xC0 <= win[i + 2] <= 0xC7:
            out.append(struct.unpack_from("<i", win, i + 3)[0])       # mov r64, imm32
            i += 7
        elif b == 0x6A:                                               # push imm8
            out.append(win[i + 1])
            i += 2
        else:
            i += 1
    return out


def main(argv):
    path = argv[1] if len(argv) > 1 else "./bin"
    minlen = int(argv[2]) if len(argv) > 2 else 4
    blob = open(path, "rb").read()
    secs = elf_sections(blob)
    if ".rodata" not in secs:
        raise SystemExit("no .rodata (not an ELF, or fully stripped section headers)")
    ro_a, _, ro_s = secs[".rodata"]
    spans = [(a, a + s, o) for (a, o, s) in secs.values() if a and s]

    def read(vaddr, n):
        for lo, hi, off in spans:
            if lo <= vaddr and vaddr + n <= hi:
                return blob[off + vaddr - lo: off + vaddr - lo + n]
        return None

    def ok(data):
        return data is not None and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in data)

    is64 = blob[4] == 2
    psz, fmt = (8, "<Q") if is64 else (4, "<I")
    found = {}

    # 1. static string headers: two adjacent words, first into .rodata, second a small length
    for name in (".rodata", ".data.rel.ro", ".data", ".noptrdata"):
        if name not in secs:
            continue
        _, off, size = secs[name]
        for i in range(0, max(0, size - 2 * psz + 1), psz):
            ptr, = struct.unpack_from(fmt, blob, off + i)
            ln, = struct.unpack_from(fmt, blob, off + i + psz)
            if ro_a <= ptr < ro_a + ro_s and minlen <= ln <= 4096:
                data = read(ptr, ln)
                if ok(data):
                    found.setdefault((ptr, ln), data)

    # 2. code constructions: lea rX,[rip+d] then a length immediate within 16 bytes
    if ".text" in secs:
        taddr, toff, tsize = secs[".text"]
        text = blob[toff:toff + tsize]
        for m in LEA_RIP.finditer(text):
            disp, = struct.unpack("<i", m.group(2))
            target = taddr + m.end() + disp          # RIP points past the instruction
            if not (ro_a <= target < ro_a + ro_s):
                continue
            for ln in imm_lengths(text[m.end():m.end() + 16]):
                if minlen <= ln <= 4096:
                    data = read(target, ln)
                    if ok(data):
                        found.setdefault((target, ln), data)
                        break

    for ptr, ln in sorted(found):
        print("0x%08x %4d  %s" % (ptr, ln, found[(ptr, ln)].decode("utf-8", "replace")))
    print("# %d constants recovered" % len(found), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

```sh
python3 go_strings.py ./chal 6 | grep -iE 'flag|wrong|correct|\{'   # scripts must sit together
python3 go_pclntab.py ./chal --ghidra /tmp/names.py                # then run it in Ghidra
```

## Variants & pitfalls

* **`strings` lies.** A "flag" read from raw `strings` output carries the next constant's bytes
  glued on; confirm the length from the `(ptr,len)` pair before submitting.
* **CGO.** `CGO_ENABLED=1` links libc dynamically so `ltrace` sees the C half; `CGO_ENABLED=0`
  gives a static blob where only `strace` helps. `-ldflags "-s -w"` still leaves pclntab.
* **Go PE binaries** hide pclntab in `.rdata` with no section-name hint; the brute-force magic
  scan covers that, and GoReSym handles PE and Mach-O properly.
* **`garble`** hashes names, wipes build info, and with `-literals` encrypts strings at init;
  attack it dynamically by breaking after `runtime.slicebytetostring`.
* **Register-ABI mis-decompilation** is the top source of wrong Ghidra output on 1.17+: fix the
  signature by hand whenever a function looks argument-less but reads RAX/RBX.
* **Bounds checks** (`runtime.panicIndex`, `panicSliceB`) shatter loops into many blocks.
* **Maps are opaque statically** - `m[k]` is a hashed bucket lookup; dump contents at runtime.

## Tools

* **GoReSym** (Mandiant) - pclntab/moduledata symbol recovery, ELF/PE/Mach-O, JSON output.
* **GolangAnalyzerExtension** - Ghidra: names, types, string structs, register ABI.
* **golang_loader_assist.py** - IDAPython renamer; **radare2** `aa` + `afl~main.` also works.
* **`go tool objdump -s 'main\.' ./bin`** - official disassembler, Go pseudo-assembly; **Delve
  (`dlv`)** - source-level debugger: `goroutines`, `stack`, `locals`, `print`.

## References

- Go runtime source `src/runtime/symtab.go` (pclntab header, `_func`) and `runtime2.go`
  (`g`, `hchan`, `itab`, `iface`, `eface`).
- Go internal ABI spec: `src/cmd/compile/abi-internal.md` in the Go tree.
- GoReSym: github.com/mandiant/GoReSym ; GolangAnalyzerExtension:
  github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension
