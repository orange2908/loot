---
title: "Python Bytecode - pyc, PyInstaller, Nuitka and Bytecode Patching"
category: rev
subcategory: python
type: technique
tags: [python, pyc, bytecode, marshal, uncompyle6, decompyle3, pycdc, pycdas, pyinstaller, pyinstxtractor, py2exe, cx-freeze, nuitka, pyarmor, dis, code-object, co-consts, decompiler]
difficulty: easy
summary: "Recover source from .pyc and frozen executables: fix the header, decompile with pycdc/uncompyle6, or read co_consts and the dis listing directly."
when_to_use:
  - "You have a .pyc, .pyo or a PyInstaller/py2exe/cx_Freeze executable"
  - "The decompiler errors out and you need the bytecode disassembly instead"
  - "You want to patch a check inside a compiled Python program"
  - "strings shows PyInstaller, _MEIPASS, python3xx.dll or Nuitka"
tools: [pycdc, uncompyle6, decompyle3, pyinstxtractor, python, xxd]
related: [dotnet-reversing, java-bytecode-reversing, javascript-deobfuscation, triage-unknown-binary, crackme-patterns, packers-and-unpacking]
---

## TL;DR

A `.pyc` is a small header plus a `marshal`-serialised code object. If the decompiler works
you get source back; if it does not, `marshal.load` the code object yourself and read
`co_consts` (which usually contains the flag) and the `dis` listing. Frozen executables
(PyInstaller, py2exe, cx_Freeze) are archives - extract, then treat the contents as `.pyc`.

## Recognise it

```sh
file chall.pyc                 # -> "Byte-compiled Python module"
xxd -l 16 chall.pyc            # first 4 bytes are the magic; see the table below
strings -a chall | grep -aiE 'pyinstaller|_MEIPASS|python3[0-9]|pyi-|Nuitka|pytransform|pyarmor'
# PyInstaller onefile: the archive's magic cookie near EOF
xxd chall | grep -i 'MEI'
# A frozen exe also carries the Python DLL/so name, which gives you the version
strings -a chall | grep -oE 'python3[0-9]+\.(dll|so)' | sort -u
```

### pyc magic numbers

The first two bytes are a little-endian `u16` followed by `\r\n`. Common values:

| Magic (LE u16) | Bytes | Python |
|---|---|---|
| 3379 | `33 0d 0d 0a` | 3.6 |
| 3394 | `42 0d 0d 0a` | 3.7 |
| 3413 | `55 0d 0d 0a` | 3.8 |
| 3425 | `61 0d 0d 0a` | 3.9 |
| 3439 | `6f 0d 0d 0a` | 3.10 |
| 3495 | `a7 0d 0d 0a` | 3.11 |
| 3531 | `cb 0d 0d 0a` | 3.12 |
| 3571 | `f3 0d 0d 0a` | 3.13 |

Header layout: 4 bytes magic, 4 bytes **flags bitfield** (since 3.7), then either
`mtime` + `source_size` (8 bytes, timestamp-based pyc, flags bit 0 clear) or an 8-byte
source hash (hash-based pyc, flags bit 0 set). So the code object starts at offset **16** on
3.7+ and at offset **12** on 3.3-3.6. Getting this wrong is the single most common reason a
decompiler says "bad marshal data".

## Decompiling

```sh
# --- pycdc (decompyle++): the only maintained option for 3.9+ -------------
# build: git clone https://github.com/zrax/pycdc && cmake . && make
./pycdc chall.pyc > chall.py          # decompile to source
./pycdas chall.pyc | less             # DISASSEMBLE - always works, even when pycdc fails

# --- uncompyle6 / decompyle3: excellent for <= 3.8 ------------------------
pip install uncompyle6 decompyle3
uncompyle6 -o . chall.pyc
decompyle3 chall.pyc                  # a fork focused on 3.7-3.8

# --- Nothing works? Use the stdlib. It always works. ---------------------
python3 -c "import dis,marshal,sys; f=open('chall.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"
```

Rules of thumb: match the decompiler's Python to the pyc's version whenever possible
(`uncompyle6` running on 3.8 for a 3.8 pyc). `pycdas` never fails because it only decodes
instructions; treat its output as the ground truth when `pycdc` emits something odd.

## Code - parse, load and mine a pyc

```python
#!/usr/bin/env python3
"""pycdump.py - identify a .pyc, load its code object, and dump everything interesting.

    python3 pycdump.py chall.pyc            # header + recursive constant dump
    python3 pycdump.py chall.pyc --dis      # add a full disassembly of every code object
    python3 pycdump.py chall.pyc --fix 3.8  # write a repaired pyc with the right header

Note: marshal can only load code objects produced by the SAME CPython version you are
running. For a cross-version pyc, use pycdas. The header parsing below always works.
"""
import dis
import marshal
import struct
import sys
import types

MAGICS = {
    3379: "3.6", 3394: "3.7", 3413: "3.8", 3425: "3.9", 3439: "3.10",
    3495: "3.11", 3531: "3.12", 3571: "3.13",
}
VERSION_TO_MAGIC = {v: k for k, v in MAGICS.items()}


def header_info(data: bytes) -> dict:
    magic = struct.unpack_from("<H", data, 0)[0]
    version = MAGICS.get(magic, "unknown")
    info = {"magic": magic, "version": version}
    if version == "unknown":
        info["code_offset"] = 16
        return info
    major_minor = tuple(int(x) for x in version.split("."))
    if major_minor >= (3, 7):
        flags = struct.unpack_from("<I", data, 4)[0]
        info["flags"] = flags
        info["hash_based"] = bool(flags & 1)
        info["check_source"] = bool(flags & 2)
        if flags & 1:
            info["source_hash"] = data[8:16].hex()
        else:
            mtime, size = struct.unpack_from("<II", data, 8)
            info["mtime"] = mtime
            info["source_size"] = size
        info["code_offset"] = 16
    else:
        mtime = struct.unpack_from("<I", data, 4)[0]
        info["mtime"] = mtime
        info["code_offset"] = 12 if major_minor >= (3, 3) else 8
    return info


def walk(code: types.CodeType, depth: int = 0, seen: set | None = None) -> None:
    """Recursively print names and constants of a code object and its children."""
    seen = seen if seen is not None else set()
    if id(code) in seen:
        return
    seen.add(id(code))
    pad = "  " * depth
    print(f"{pad}<code {code.co_name} argcount={code.co_argcount} "
          f"nlocals={code.co_nlocals} stacksize={code.co_stacksize}>")
    if code.co_varnames:
        print(f"{pad}  varnames: {list(code.co_varnames)}")
    if code.co_names:
        print(f"{pad}  names:    {list(code.co_names)}")
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            walk(const, depth + 1, seen)
        elif isinstance(const, (bytes, str)) and len(str(const)) > 1:
            print(f"{pad}  const:    {const!r}")
        elif const is not None:
            print(f"{pad}  const:    {const!r}")


def disassemble(code: types.CodeType, depth: int = 0) -> None:
    print("\n" + "=" * 60)
    print(f"disassembly of {code.co_name}")
    print("=" * 60)
    dis.dis(code)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            disassemble(const, depth + 1)


def fix_header(data: bytes, target: str, out: str) -> None:
    """Prepend a correct 16-byte header for `target` to raw marshal data."""
    magic = VERSION_TO_MAGIC[target]
    header = struct.pack("<HBB", magic, 0x0D, 0x0A) + struct.pack("<I", 0) + b"\x00" * 8
    body = data
    if data[2:4] == b"\r\n":                    # already has some header - strip it
        body = data[16:]
    with open(out, "wb") as fh:
        fh.write(header + body)
    print(f"[+] wrote {out} with a Python {target} header")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()

    info = header_info(data)
    print(f"[*] magic {info['magic']} -> Python {info['version']}")
    for key, val in info.items():
        if key not in ("magic", "version"):
            print(f"    {key}: {val}")

    if "--fix" in sys.argv:
        target = sys.argv[sys.argv.index("--fix") + 1]
        fix_header(data, target, sys.argv[1] + ".fixed")
        return 0

    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    if info["version"] != running:
        print(f"[!] this interpreter is {running}; marshal.load will likely fail.")
        print("    Use pycdas for a cross-version disassembly.")
    try:
        code = marshal.loads(data[info["code_offset"]:])
    except Exception as exc:
        print(f"[-] marshal.loads failed: {exc}")
        return 1

    print("\n[*] constants and names:")
    walk(code)
    if "--dis" in sys.argv:
        disassemble(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`co_consts` is where flags live: docstrings, every literal, and nested code objects. A
surprising number of "compiled Python" challenges are solved by this script alone.

## Reading CPython bytecode

```
  4           0 LOAD_FAST                0 (password)
              2 LOAD_CONST               1 ('s3cr3t')
              4 COMPARE_OP               2 (==)
              6 POP_JUMP_IF_FALSE       12 (to 24)
  5           8 LOAD_GLOBAL              0 (print)
             10 LOAD_CONST               2 ('Correct!')
             12 CALL_FUNCTION            1
```

Key opcodes: `LOAD_CONST` (index into `co_consts`), `LOAD_FAST`/`STORE_FAST` (locals by index
into `co_varnames`), `LOAD_GLOBAL`/`LOAD_NAME` (`co_names`), `COMPARE_OP` (the argument
selects `<`, `<=`, `==`, `!=`, `>`, `>=`), `POP_JUMP_IF_FALSE`/`_TRUE`, `CALL_FUNCTION`
(3.10 and earlier) / `CALL` + `PRECALL` (3.11+), `BINARY_OP` (3.11+ replaces
`BINARY_ADD`/`BINARY_XOR`/... with one opcode plus an argument), `MAKE_FUNCTION`,
`EXTENDED_ARG` (prefixes an opcode to widen its argument beyond 255).

3.11+ specifics that confuse people: the interpreter is **adaptive**, so the bytecode
contains inline `CACHE` entries that `dis` hides by default. Use `dis.dis(f, show_caches=True)`
to see them, and `dis.dis(f, adaptive=True)` to see the specialised forms of a function that
has already run. Jump arguments are relative and counted in *instructions*, not bytes, from
3.10 onward.

## Bytecode patching

```python
#!/usr/bin/env python3
"""bcpatch.py - patch a function's bytecode in place, without its source.

Demonstrates the general technique: pull co_code apart, rewrite the bytes you want,
and rebuild the code object with CodeType.replace(). Works on 3.11+ and 3.8+ alike
because we only swap one COMPARE_OP argument.
"""
import dis
import sys
import types


def find_compare(code: types.CodeType) -> list[tuple[int, int]]:
    """Return [(offset, argument)] for every COMPARE_OP in the code object."""
    return [(ins.offset, ins.arg) for ins in dis.get_instructions(code)
            if ins.opname == "COMPARE_OP"]


def patch_compare(fn, new_arg: int):
    """Return a copy of `fn` whose FIRST COMPARE_OP uses `new_arg` instead."""
    code = fn.__code__
    hits = find_compare(code)
    if not hits:
        raise ValueError("no COMPARE_OP in this function")
    offset, old_arg = hits[0]
    raw = bytearray(code.co_code)
    raw[offset + 1] = new_arg & 0xFF          # the argument byte follows the opcode
    patched = code.replace(co_code=bytes(raw))
    print(f"[+] COMPARE_OP at offset {offset}: arg {old_arg} -> {new_arg}")
    return types.FunctionType(patched, fn.__globals__, fn.__name__,
                              fn.__defaults__, fn.__closure__)


def equal_arg() -> int:
    """The COMPARE_OP argument that means '=='; its encoding changed in 3.12."""
    if sys.version_info >= (3, 12):
        # 3.12 packs the comparison in the high bits and a cast flag in the low ones
        return dis.cmp_op.index("==") << 4
    return dis.cmp_op.index("==")


def not_equal_arg() -> int:
    if sys.version_info >= (3, 12):
        return dis.cmp_op.index("!=") << 4
    return dis.cmp_op.index("!=")


def check(password: str) -> bool:
    return password == "s3cr3t"


if __name__ == "__main__":
    assert check("s3cr3t") is True
    assert check("wrong") is False
    # Flip '==' into '!=' so any wrong password is accepted
    inverted = patch_compare(check, not_equal_arg())
    print("  inverted('wrong')  =", inverted("wrong"))
    print("  inverted('s3cr3t') =", inverted("s3cr3t"))
    print("[+] original disassembly:")
    dis.dis(check)
    print("[+] patched disassembly:")
    dis.dis(inverted)
```

To persist a patch into a `.pyc`, rebuild the module's top-level code object the same way
and write `header + marshal.dumps(code)` back out. Writing the *source* and recompiling is
almost always easier when you have decompiled output.

## Frozen executables

### PyInstaller

```sh
# 1. Extract. pyinstxtractor works for all PyInstaller 2.x-6.x archives.
python3 pyinstxtractor.py chall.exe
#   -> chall.exe_extracted/ containing:
#        <name>.pyc            the entry-point script (often header-less!)
#        PYZ-00.pyz_extracted/ every bundled module as .pyc
#        struct, pyimod0*.pyc  PyInstaller's own bootstrap (ignore)
#        *.dll / *.so          the CPython runtime - tells you the version

# 2. The extractor prints the Python version. Note it.
# 3. Extracted pyc files may be missing the 16-byte header. Repair before decompiling:
python3 pycdump.py chall.exe_extracted/chall.pyc --fix 3.11

# 4. Decompile the entry point and the interesting modules
./pycdc chall.exe_extracted/chall.pyc.fixed > main.py
grep -rl 'flag\|check\|verify' chall.exe_extracted/PYZ-00.pyz_extracted/ | head
```

The structure of a onefile PyInstaller binary: the normal executable, then a **CArchive**
appended at the end, terminated by a magic cookie `MEI\x0c\x0b\x0a\x0b\x0e` followed by the
archive length, TOC offset and the Python version. The TOC lists every entry with a
compression flag and a type character (`s` = source script, `m`/`M` = module, `z` = PYZ
archive, `b` = binary). `pyinstxtractor` walks exactly that.

### py2exe and cx_Freeze

```sh
# py2exe: the pyc files live in the PE resource named PYTHONSCRIPT
python3 -c "
import pefile,sys
pe = pefile.PE(sys.argv[1])
for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    print(e.name, e.struct.Id)
" chall.exe
# The library.zip beside the exe (or embedded) holds the rest of the modules
unzip -o library.zip -d lib/

# cx_Freeze: modules are in a zip appended to the exe, or in lib/library.zip
unzip -l chall.exe 2>/dev/null || unzip -l lib/library.zip
```

### Nuitka - not recoverable

Nuitka translates Python to C and compiles it. There is **no bytecode to decompile**.
Recognise it by `Nuitka`, `__compiled__`, `nuitka_` prefixed symbols, or a `.dist` folder
with `python3xx.dll` and one huge binary.

```sh
strings -a chall | grep -aE 'Nuitka|__compiled__|nuitka_' | head
nm -D chall 2>/dev/null | grep -i nuitka | head
```

What to do instead: treat it as a native binary. The constants (your strings, including
flags) are still present as a blob that Nuitka unmarshals at startup - `strings -a` and
`binwalk` often hand you the flag. For logic, use ordinary native RE plus dynamic analysis,
and remember the C code still calls the CPython C API (`PyObject_RichCompare`,
`PyUnicode_FromString`), so breakpoints on those APIs are extremely informative.

### PyArmor and other obfuscators

Signals: a `pytransform` / `pyarmor_runtime` module, `__pyarmor__(__name__, __file__, b'...')`
at the top of every file, and a `.so`/`.dll` runtime. The code objects are decrypted in
memory at import time, so the generic answer is **let it run and dump**:

```python
#!/usr/bin/env python3
"""dumpcode.py - run a protected script and marshal out every code object it executes.

    python3 dumpcode.py target.py

Audit hooks (3.8+) fire on exec/compile, giving you the decrypted code object
before it runs. Run this in a VM: you are executing untrusted code.
"""
import marshal
import runpy
import sys
import types

DUMPED: list[types.CodeType] = []


def hook(event: str, args: tuple) -> None:
    if event in ("exec", "compile") and args:
        obj = args[0]
        if isinstance(obj, types.CodeType):
            DUMPED.append(obj)
            name = f"dumped_{len(DUMPED):03d}_{obj.co_name or 'module'}.marshal"
            with open(name, "wb") as fh:
                fh.write(marshal.dumps(obj))
            print(f"[+] {name}  ({obj.co_filename})", file=sys.stderr)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: dumpcode.py <script.py>")
        return 1
    sys.addaudithook(hook)
    target = sys.argv[1]
    sys.argv = sys.argv[1:]
    try:
        runpy.run_path(target, run_name="__main__")
    except SystemExit:
        pass
    except Exception as exc:
        print(f"[!] target raised: {exc}", file=sys.stderr)
    print(f"[+] dumped {len(DUMPED)} code object(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Each dumped `.marshal` can be given a pyc header (`pycdump.py --fix`) and decompiled.

## Variants & pitfalls

- **Wrong header offset** (12 vs 16) is the #1 cause of "bad marshal data". Check the magic
  first, then pick the offset.
- **`marshal` is version-locked**: a 3.11 `marshal.loads` cannot read a 3.8 code object
  reliably. Either install the matching interpreter (`pyenv`) or use `pycdas`.
- **`.pyo` is just a `.pyc`** compiled with `-O`; asserts and docstrings may be stripped.
- **`__pycache__/mod.cpython-311.pyc`** encodes the version in the filename - free version
  identification.
- **Source may be recoverable without any of this**: check for a `.py` left in the archive,
  a `.pyc` alongside its `.py`, or git artefacts.
- **Decompilers lie about control flow** on optimised code. When the decompiled logic looks
  impossible, trust `pycdas`/`dis`.
- **3.11+ zero-cost exceptions** removed `SETUP_FINALLY`; older decompilers produce nonsense
  for try/except. Use pycdc built from a recent commit.
- **Flag not in `co_consts`?** It may be assembled at runtime from `bytes` arithmetic; read
  the disassembly or just run the function in a REPL with `exec(code)`.
- **Run untrusted Python in a container**, always - importing the module executes it.

## Tools

- `pycdc` / `pycdas` (decompyle++) - decompiler and disassembler for modern versions.
- `uncompyle6` / `decompyle3` - best quality for <= 3.8.
- `pyinstxtractor` - PyInstaller archive extraction.
- `dis`, `marshal`, `types.CodeType.replace` - the stdlib, which never fails.
- `pyenv` - install the exact interpreter a pyc needs.
- `xdis` - cross-version bytecode disassembly as a library.

## References

- CPython source `Lib/importlib/_bootstrap_external.py` - the pyc header layout and the
  `MAGIC_NUMBER` history used in the table above.
- Python documentation for the `dis` module (opcode semantics, `show_caches`, `adaptive`).
- PEP 552 - hash-based pyc files (the flags field described above).
