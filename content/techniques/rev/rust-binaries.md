---
title: "Rust Binaries - Mangling, Fat Pointers, Panic Metadata"
category: rev
subcategory: rust
type: technique
tags: [rust, rustc, rustfilt, legacy-mangling, v0-mangling, demangling, panic, bounds-check, fat-pointer, str, string, vec, option, niche-optimisation, monomorphisation, lang-start, core-fmt, ghidra, ida, cargo]
difficulty: hard
summary: "Identify Rust by panic metadata, demangle legacy/v0 symbols, and read &str/String/Vec/Option layouts so decompiler output stops looking like noise."
when_to_use:
  - "Symbols look like `_ZN4core3fmt9Arguments6new_v117h9a3f...E` or start with `_R`"
  - "`strings` shows `src/main.rs`, `index out of bounds`, `called Option::unwrap() on a None`"
  - "Every loop body is followed by a cold `panic_bounds_check` tail in a 300 KB+ static binary"
  - "You need the crate name and source line numbers out of a stripped release build"
tools: [ghidra, ida, radare2, rustfilt, gdb, nm, python]
related: [triage-unknown-binary, ghidra-workflow, go-binaries, cpp-vtables-stl, ida-r2-binja-workflow, crackme-patterns]
---

## TL;DR

Rust release binaries are static and bloated by monomorphisation, but they leak plenty: panic
messages carry source paths and line numbers, symbols use a recoverable mangling scheme, and
`&str`/`String`/`Vec` have fixed layouts. Demangle first, apply the layouts, and it reads.

## Recognise it

| Signal | Check |
|---|---|
| Panic metadata | `strings -a ./bin \| grep -E 'src/(main\|lib)\.rs'` plus line/col numbers |
| Panic messages | `index out of bounds: the len is`, `attempt to add with overflow`, `called \`Option::unwrap()\` on a \`None\` value` |
| Mangling | `nm ./bin \| grep -c '17h[0-9a-f]\{16\}E'` -> hundreds; or `_RN`/`_RI` for v0 |
| No `strcmp` | string equality is a length test then `bcmp`; crate paths appear as `.../index.crates.io-<hash>/clap-4.4.6/src/parser/mod.rs` |

```sh
# Demangle the whole symbol table (rustfilt handles both legacy and v0)
nm ./bin | rustfilt | grep -iE 'main|check|flag|validate'
# Crate names + dependency versions the panic machinery leaked into .rodata
strings -a ./bin | grep -oE '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src/[^ ]+' | sort -u
strings -a ./bin | grep -m1 -E 'rustc version [0-9.]+'    # build fingerprint
```

## How it works

### Name mangling

**Legacy** (the default before v0): length-prefixed path components, terminated by `E`, with a
`17h<16 hex>` hash as the final component:

```text
_ZN5chal48validate17h4f2a93bd8f1c07e2E
 ^^ ^     ^        `-- 17h + 16 hex: metadata hash, strip it
 |  |     `----------- 8-char component "validate"
 |  `----------------- 5-char component "chal4"
 `-------------------- Rust/Itanium prefix          => chal4::validate
```

Escapes: `$LT$`/`$GT$` = `<`/`>`, `$u20$` = space, `$RF$` = `&`, `$C$` = `,`, `$BP$` = `*`,
`$u7b$`/`$u7d$` = `{`/`}`, and `..` means `::` - so
`_ZN50_$LT$chal4..Cipher$u20$as$u20$core..fmt..Debug$GT$3fmt17h...E` demangles to
`<chal4::Cipher as core::fmt::Debug>::fmt`.

**v0** starts with `_R` and is a real grammar - nested paths (`N`), generics (`I`), lifetimes,
types and const values, no hash and no `..`/`::` ambiguity, so it round-trips exactly. After
`cargo install rustfilt`, `objdump -d ./bin | rustfilt | less` demangles a whole disassembly
inline. Ghidra's v0 support is patchy: pre-demangle and import the names via a script.

### `&str` is a fat pointer

`let s: &str = "flag{demo}";` is two words, `(ptr, len)`, with **no NUL** - so `.rodata` is one
run-on blob exactly like Go, and a function taking one `&str` has *two* ABI parameters:

```asm
lea  rdi, [rip+0x2a9f1]   ; data pointer into the .rodata blob
mov  esi, 10              ; length
call chal4::validate
```

### Owned container layouts (x86-64, stable rustc)

| Type | Size | Layout |
|---|---|---|
| `&str`, `&[T]` | 16 | `{ ptr, len }` |
| `String` | 24 | `{ ptr, cap, len }` - **capacity before length**; reading `+0x8` as the length is the most common Rust RE mistake |
| `Vec<T>` | 24 | `{ ptr, cap, len }` |
| `&dyn Trait` | 16 | `{ data, vtable }`; vtable = `{drop_in_place, size, align, methods...}` |

### `Option` / `Result` niche optimisation

| Type | Size | Encoding |
|---|---|---|
| `Option<&T>`, `Option<Box<T>>`, `Option<fn()>` | 8 | `None` == null pointer, no tag byte |
| `Option<NonZeroU32>` | 4 | `None` == 0 |

A null-pointer test is therefore often a literal `match opt { None => .., Some(x) => .. }`.

### Bounds checks are free source-line markers

Every `v[i]` emits `cmp idx,len; jae .oob`. The cold block loads a `&'static Location`
(`{file_ptr, file_len, line u32, col u32}`) and calls `core::panicking::panic_bounds_check` -
decode it and you have the exact source line of the loop you are reading:

```asm
  cmp    rbx, qword [rsp+0x18]     ; i vs len
  jae    .oob
  movzx  eax, byte [r14+rbx]       ; the real body
.oob:
  lea    rdx, [rip+0x31a02]        ; &Location { "src/main.rs", 11, 42, 9 }
  call   core::panicking::panic_bounds_check
```

### `format!` / `println!`

`println!("{}", x)` builds `core::fmt::Arguments { pieces: &[&str], fmt: Option<&[Placeholder]>,
args: &[ArgumentV1] }`. `pieces` holds the literal chunks *between* the `{}`; `args` is an array
of `(value_ptr, formatter_fn_ptr)` pairs. Expect a `lea` of a static `[&str; N]`, a `lea` of a
stack-built argument array, then `Arguments::new_v1` and `std::io::_print` - reassembling
`pieces` recovers the original format string.

### Finding `main`

`rustc` emits a C `main` that hands the Rust `main` to `std::rt::lang_start` as a **function
pointer in RDI** - `lea rdi,[rip+0x1e2]; jmp std::rt::lang_start_internal`. Find `lang_start`,
take its first argument. Stripped? Break on `std::io::_print` and walk the stack back, or read
the `Location` structs - they name the file `main` lives in.

## Workflow

1. `strings -a ./bin | grep -E 'src/.*\.rs|rustc version|crates.io'` - crate name, dependency
   versions and file names, before opening a disassembler.
2. `nm ./bin | rustfilt > syms.txt`, or `rust_syms.py` below when `rustfilt` is unavailable;
   import the names and enable *Demangler GNU* for legacy symbols.
3. Define `Str{ptr,len}` and `RustVec{ptr,cap,len}`, then retype every local the decompiler
   renders as three adjacent 8-byte stack slots.
4. Recover `&str` constants with `rust_strs.py`; grep for the prompt and failure text.
5. Find the check - a `bcmp` with a constant length, or an inlined iterator loop - then run
   `gdb -q ./bin -ex 'break bcmp' -ex run -ex 'x/s $rdi' -ex 'x/s $rsi'`.

## Code

### A Rust flag checker in Ghidra

```rust
fn check(input: &str) -> bool {
    input.bytes().enumerate().map(|(i, b)| b ^ (i as u8 * 3 + 0x41))
         .eq(EXPECTED.iter().copied())
}
```

```c
bool chal4_check(char *input_ptr, ulong input_len)
{
  ulong i;  byte computed;  byte *expected;
  if (input_len != 0x18) {                              /* 1 */
    return false;
  }
  i = 0;
  expected = &EXPECTED;                                 /* 2 */
  do {
    if (i >= input_len) {                               /* 3 */
      core::panicking::panic_bounds_check(i, input_len, &LOC_main_rs_11);
    }
    computed = input_ptr[i] ^ ((char)i * 3 + 0x41);     /* 4 */
    if (computed != expected[i]) {                      /* 5 */
      return false;
    }
    i = i + 1;
  } while (i != 0x18);
  return true;
}
```

1. `&str` arrived as two parameters; `.eq()` short-circuits on a length mismatch, so `0x18`
   **is the flag length** (24 bytes).
2. `EXPECTED` is a `&[u8; 24]` in `.rodata` - select 24 bytes in Ghidra and press `[`.
3. The bounds check. `LOC_main_rs_11` is a `Location`: ptr to `"src/main.rs"`, len 11, line 11,
   column 9 - ignore the branch, keep the line number.
4. The closure was inlined - `b ^ (i as u8 * 3 + 0x41)`; `(char)i` is the `as u8` truncation.
5. `.eq()` fused into the loop: compare-and-bail, no intermediate collection. Release does this
   to every chain; a debug build shows nested `Iterator::next` calls. Inversion is then
   `flag[i] = EXPECTED[i] ^ ((i * 3 + 0x41) & 0xff)`.

### Extract and demangle symbols

```python
#!/usr/bin/env python3
"""Dump Rust symbols from an ELF and demangle legacy (_ZN...17h<hash>E) names.

v0 (_R...) symbols are approximated here - pipe those through `rustfilt` for exact output.
Usage: python3 rust_syms.py ./bin [filter-substring]
"""
import re
import subprocess
import sys

LEGACY = re.compile(r"^_ZN(.+)E$")
HASH = re.compile(r"^h[0-9a-f]{16}$")     # component form of the "17h<hash>" suffix
ESCAPES = {"$LT$": "<", "$GT$": ">", "$LP$": "(", "$RP$": ")", "$C$": ",", "$RF$": "&",
           "$BP$": "*", "$u20$": " ", "$u27$": "'", "$u5b$": "[", "$u5d$": "]",
           "$u7b$": "{", "$u7d$": "}", "$u3b$": ";", "$SP$": "@"}


def unescape(s):
    s = s[1:] if s.startswith("_$") else s    # rustc prefixes "_" before a leading escape
    for k, v in ESCAPES.items():
        s = s.replace(k, v)
    return s.replace("..", "::")


def demangle_legacy(sym):
    """_ZN5chal48validate17h<hash>E -> chal4::validate ; None when not a legacy symbol."""
    m = LEGACY.match(sym)
    if not m:
        return None
    body, parts, i = m.group(1), [], 0    # components are <declen><name>, repeated
    while i < len(body):
        j = i
        while j < len(body) and body[j].isdigit():
            j += 1
        if j == i:
            return None                       # not length-prefixed -> not legacy
        n = int(body[i:j])
        comp = body[j:j + n]
        if len(comp) != n:
            return None
        parts.append(comp)
        i = j + n
    if parts and HASH.match(parts[-1]):
        parts.pop()                           # drop the crate-disambiguator hash
    return "::".join(unescape(p) for p in parts)


def demangle_v0(sym):
    """Approximate v0: pick out the <len><ident> runs; use rustfilt for an exact answer."""
    out, i = [], 2
    while i < len(sym):
        j = i
        while j < len(sym) and sym[j].isdigit():
            j += 1
        n = int(sym[i:j]) if j > i else 0
        comp = sym[j:j + n]
        if 0 < n <= 64 and len(comp) == n and comp.isidentifier():
            out.append(comp)
            i = j + n
        else:
            i = max(j, i + 1)
    return "::".join(out) + "  # approx, use rustfilt"


def demangle(sym):
    if sym.startswith("_ZN"):
        return demangle_legacy(sym) or sym
    return demangle_v0(sym) if sym.startswith("_R") else sym

def elf_functions(path):
    """[(addr, mangled_name)] for FUNC symbols, via readelf."""
    txt = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True,
                         check=True).stdout
    rows = (ln.split() for ln in txt.splitlines())
    return [(int(f[1], 16), f[7].split("@")[0]) for f in rows if len(f) > 7 and f[3] == "FUNC"]


def main(argv):
    path = argv[1] if len(argv) > 1 else "./bin"
    needle = argv[2] if len(argv) > 2 else ""
    assert demangle_legacy("_ZN5chal48validate17h4f2a93bd8f1c07e2E") == "chal4::validate"
    seen = set()
    for addr, sym in elf_functions(path):
        pretty = demangle(sym)
        if (needle and needle not in pretty) or pretty in seen:
            continue
        seen.add(pretty)
        print("0x%08x  %s" % (addr, pretty))
    print("# %d unique symbols" % len(seen), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

### Recover `&str` constants from `(ptr, len)` pairs

```python
#!/usr/bin/env python3
"""Recover Rust &str/&[u8] constants by finding (ptr,len) pairs that target .rodata.

Bodies are stored unterminated; the header lives either in a static slice table
(.rodata/.data.rel.ro) or is materialised in code as lea rX,[rip+d32] + a length immediate.
Usage: python3 rust_strs.py ./bin [minlen]
"""
import re
import struct
import sys

LEA_RIP = re.compile(rb"\x48\x8d([\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(....)", re.S)


def elf_sections(blob):
    """{name: (vaddr, file_off, size)} for a 64-bit little-endian ELF."""
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise SystemExit("expected a 64-bit ELF")
    shoff, = struct.unpack_from("<Q", blob, 0x28)
    entsz, num, stridx = struct.unpack_from("<HHH", blob, 0x3A)
    raw = []
    for i in range(num):                      # sh_name u32 @0, sh_addr/offset/size @0x10
        b = shoff + i * entsz
        raw.append(struct.unpack_from("<I", blob, b)
                   + struct.unpack_from("<QQQ", blob, b + 0x10))
    stro = raw[stridx][2]
    secs = {}
    for nameoff, addr, off, size in raw:
        e = blob.index(b"\x00", stro + nameoff)
        secs[blob[stro + nameoff:e].decode()] = (addr, off, size)
    return secs


def lengths_after(win):
    out, i = [], 0    # length immediates rustc emits right after loading the data pointer
    while i < len(win) - 4:
        b = win[i]
        if b in (0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF):                # mov r32, imm32
            out.append(struct.unpack_from("<I", win, i + 1)[0])
            i += 5
        elif b == 0x48 and win[i + 1] == 0xC7 and 0xC0 <= win[i + 2] <= 0xC7:
            out.append(struct.unpack_from("<i", win, i + 3)[0])      # mov r64, imm32
            i += 7
        else:
            i += 1
    return out


def main(argv):
    path = argv[1] if len(argv) > 1 else "./bin"
    minlen = int(argv[2]) if len(argv) > 2 else 4
    blob = open(path, "rb").read()
    secs = elf_sections(blob)
    if ".rodata" not in secs:
        raise SystemExit("no .rodata")
    ro_a, _ro_o, ro_s = secs[".rodata"]
    spans = [(a, a + s, o) for (a, o, s) in secs.values() if a and s]

    def read(vaddr, n):                       # vaddr -> bytes, across all mapped sections
        for lo, hi, off in spans:
            if lo <= vaddr and vaddr + n <= hi:
                return blob[off + vaddr - lo: off + vaddr - lo + n]
        return None

    def utf8_ok(data):                        # printable and valid UTF-8
        try:
            return all(c >= 0x20 or c in (9, 10, 13) for c in data) and bool(data.decode())
        except UnicodeDecodeError:
            return False

    found = {}
    for name in (".rodata", ".data.rel.ro", ".data"):   # 1. static [ptr u64][len u64] headers
        if name not in secs:
            continue
        _a, off, size = secs[name]
        for i in range(0, max(0, size - 15), 8):
            ptr, ln = struct.unpack_from("<QQ", blob, off + i)
            if ro_a <= ptr < ro_a + ro_s and minlen <= ln <= 8192:
                if (data := read(ptr, ln)) and utf8_ok(data):
                    found.setdefault((ptr, ln), data)

    if ".text" in secs:   # 2. lea rX,[rip+disp32] then a length immediate within 16 bytes
        taddr, toff, tsize = secs[".text"]
        text = blob[toff:toff + tsize]
        for m in LEA_RIP.finditer(text):
            disp, = struct.unpack("<i", m.group(2))
            target = taddr + m.end() + disp          # RIP is past the instruction
            if not (ro_a <= target < ro_a + ro_s):
                continue
            for ln in lengths_after(text[m.end():m.end() + 16]):
                if minlen <= ln <= 8192 and (data := read(target, ln)) and utf8_ok(data):
                    found.setdefault((target, ln), data)
                    break

    for ptr, ln in sorted(found):
        print("0x%08x %5d  %s" % (ptr, ln, found[(ptr, ln)].decode("utf-8", "replace")))
    print("# %d &str constants recovered" % len(found), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

```sh
python3 rust_strs.py ./chal 5 | grep -iE 'flag|wrong|src/'  # prompts, paths, failure messages
python3 rust_syms.py ./chal check                           # candidate checker functions
```

## Variants & pitfalls

* **Debug vs release.** Debug keeps every `Iterator::next` and `unwrap` as a real call - verbose
  but readable; `--release` fuses whole chains into one loop. CTF binaries are usually release,
  and `std` is bundled either way so `ltrace` sees nothing; use `strace` or gdb.
* **`String` is `(ptr, cap, len)`** - in gdb the length is `p *(unsigned long*)($rdi+16)`.
* **Monomorphisation bloat**: `Vec<u8>` and `Vec<u32>` yield two full copies of every method, so
  identical-looking functions at different addresses are usually one generic. Hash suffixes also
  change per build - never hard-code a `17h...` value in a script.
* **`panic = "abort"`** removes landing pads; `strip = true` kills symbols, but panic `Location`
  strings survive as data. `no_std` builds have no panic strings at all.
* **`==` on `&str`** is a length check plus `bcmp` - the highest-yield single breakpoint.

## Tools

* **rustfilt** (`cargo install rustfilt`) - legacy + v0 demangler, usable as a stream filter;
  **`nm -C` / `c++filt`** handle legacy Rust through the Itanium path.
* **Ghidra** *Demangler GNU* for legacy names; import v0 names from a script. **gdb**
  `set language rust` when DWARF survived; **radare2** `rabin2 -s ./bin | rustfilt`.

## References

- Rust RFC 2603 - the v0 mangling scheme; `rustc_symbol_mangling` in the rustc source.
- `library/core/src/panicking.rs` (`panic_bounds_check`, `Location`) and
  `library/alloc/src/string.rs` / `raw_vec.rs` (the `String`/`Vec` field order).
- The Rustonomicon, on `repr(Rust)` layout and niche optimisation; rustfilt at
  github.com/luser/rustfilt
