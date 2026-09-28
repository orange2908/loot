---
title: ".NET Reversing - dnSpy, de4dot and Patching IL"
category: rev
subcategory: dotnet
type: technique
tags: [dotnet, csharp, dnspy, ilspy, dotpeek, de4dot, confuserex, il, cil, msil, managed-pe, mono, unity, il2cpp, single-file, reflection, monodis, patching]
difficulty: easy
summary: "A .NET binary decompiles back to near-original C#: identify the CLR header, run de4dot if obfuscated, read it in dnSpy, then edit the method and save."
when_to_use:
  - "file/rabin2 says the PE is a .NET assembly, or the only import is mscoree.dll"
  - "strings shows #Strings, #Blob, #US, #GUID or System.Private.CoreLib"
  - "The challenge is a Unity game, a WPF app, or a PowerShell-adjacent EXE"
  - "You need to change a check and re-run rather than recover an input"
tools: [dnspy, ilspy, de4dot, ilspycmd, monodis, il2cppdumper, python]
related: [java-bytecode-reversing, windows-pe-reversing, packers-and-unpacking, obfuscation-deobfuscation, crackme-patterns, triage-unknown-binary]
---

## TL;DR

.NET compiles to CIL plus full metadata (names, types, signatures), so decompilation is
essentially lossless unless an obfuscator ran. Workflow: confirm it is managed, run `de4dot`
if the names look like ``, open in dnSpy/ILSpy, read the C#, and if you need to
change behaviour, edit the method in dnSpy and save the module.

## Recognise it

```sh
# 1. file usually says it outright
file chall.exe          # -> "PE32 executable ... Mono/.Net assembly"
# 2. radare2 shows the language and the only native import
rabin2 -I chall.exe | grep -Ei 'lang|bintype'
rabin2 -i chall.exe | grep -i mscoree      # _CorExeMain is the single native import
# 3. The metadata stream names are plain ASCII in the file
strings -a chall.exe | grep -E '^#(~|-|Strings|US|Blob|GUID)$'
strings -a chall.exe | grep -E 'v4\.0\.30319|System\.Private\.CoreLib|mscorlib'
# 4. The authoritative check: the COM descriptor data directory (index 14) is non-zero
python3 isdotnet.py chall.exe        # script below
```

Three flavours you will meet:

| Flavour | Signal | Tooling |
|---|---|---|
| .NET Framework (v4.0.30319) | `mscorlib`, `mscoree.dll` import | dnSpy, ILSpy |
| .NET Core / 5-8 | `System.Private.CoreLib`, a `.dll` beside a native `.exe` apphost | dnSpy(Ex), ILSpy |
| .NET single-file publish | one large `.exe`, bundle signature below | extract first |
| Mono / Unity | `Assembly-CSharp.dll` under `*_Data/Managed/` | dnSpy |
| Unity IL2CPP | `GameAssembly.dll` + `global-metadata.dat`, no managed DLLs | Il2CppDumper |
| Native AOT | no CLR header at all; it is a normal native PE | ordinary RE |

## Code - is this a .NET assembly?

```python
#!/usr/bin/env python3
"""isdotnet.py - detect a managed PE and dump its CLR header and metadata streams.

Pure stdlib: parses the DOS/NT headers, the COM descriptor data directory (index 14),
the CLI header, and the metadata root (BSJB signature, version string, stream table).

Usage: python3 isdotnet.py chall.exe
"""
import struct
import sys

DIR_COM_DESCRIPTOR = 14


def rva_to_off(sections: list[dict], rva: int) -> int | None:
    for sec in sections:
        if sec["va"] <= rva < sec["va"] + max(sec["vsize"], sec["rsize"]):
            return sec["raw"] + (rva - sec["va"])
    return None


def parse(path: str) -> int:
    with open(path, "rb") as fh:
        data = fh.read()

    if data[:2] != b"MZ":
        print("[-] not a PE (no MZ)")
        return 1
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        print("[-] not a PE (no PE signature)")
        return 1

    n_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    pe32plus = magic == 0x20B
    print(f"[*] {path}: PE{'32+' if pe32plus else '32'}, {n_sections} sections")

    # Data directories start after the fixed part of the optional header
    dd_off = opt_off + (112 if pe32plus else 96)
    com_rva, com_size = struct.unpack_from("<II", data, dd_off + DIR_COM_DESCRIPTOR * 8)
    if com_rva == 0:
        print("[-] no COM descriptor directory -> NATIVE binary, not .NET")
        return 1
    print(f"[+] managed: CLR header rva={com_rva:#x} size={com_size:#x}")

    sec_off = opt_off + opt_size
    sections = []
    for i in range(n_sections):
        base = sec_off + i * 40
        name = data[base:base + 8].rstrip(b"\0").decode(errors="replace")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, base + 8)
        sections.append({"name": name, "va": va, "vsize": vsize, "raw": raw, "rsize": rsize})
        print(f"    section {name:<8} va={va:#010x} vsize={vsize:#x} raw={raw:#x}")

    clr_off = rva_to_off(sections, com_rva)
    if clr_off is None:
        print("[-] CLR header RVA not mapped")
        return 1
    (cb, major, minor, md_rva, md_size, flags, entry) = struct.unpack_from(
        "<IHHIIII", data, clr_off)
    print(f"[+] CLI header: runtime {major}.{minor}, flags={flags:#x}, "
          f"entrypoint token={entry:#x}")
    print("    ILONLY" if flags & 1 else "    mixed mode (contains native code)")
    if flags & 2:
        print("    32BITREQUIRED")
    if flags & 8:
        print("    STRONGNAMESIGNED")

    md_off = rva_to_off(sections, md_rva)
    if md_off is None or data[md_off:md_off + 4] != b"BSJB":
        print("[-] metadata root not found")
        return 1
    ver_len = struct.unpack_from("<I", data, md_off + 12)[0]
    version = data[md_off + 16:md_off + 16 + ver_len].rstrip(b"\0").decode(errors="replace")
    print(f"[+] metadata version: {version}")

    p = md_off + 16 + ver_len
    p += 2                                  # flags
    n_streams = struct.unpack_from("<H", data, p)[0]
    p += 2
    print(f"[+] {n_streams} metadata streams:")
    for _ in range(n_streams):
        s_off, s_size = struct.unpack_from("<II", data, p)
        p += 8
        end = data.index(b"\0", p)
        name = data[p:end].decode(errors="replace")
        p = end + 1
        p = (p + 3) & ~3                    # 4-byte aligned
        print(f"    {name:<10} offset={s_off:#x} size={s_size:#x}")
    print("\n[+] open it with: dnSpy / ILSpy / ilspycmd")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: isdotnet.py <file.exe|file.dll>")
        return 1
    return parse(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
```

Stream names and what they hold: `#~` (or `#-` when uncompressed/edited) the metadata
tables, `#Strings` identifier names, `#US` user strings (all your string literals, UTF-16),
`#Blob` signatures and constants, `#GUID` module GUIDs.

## Decompiling

```sh
# --- GUI (Windows): the default choice ------------------------------------
# dnSpy / dnSpyEx: open the exe, browse the tree, F5 to decompile, Ctrl+Shift+F to search all
# Right-click a method > "Analyze" to get callers/callees (the killer feature)
# View > "IL with C#" to see both at once

# --- Cross-platform CLI ----------------------------------------------------
dotnet tool install -g ilspycmd
ilspycmd -p -o ./src chall.exe        # -p = split into one .cs file per type
ilspycmd -il chall.exe                # raw IL to stdout

# --- Mono tooling (available on Linux from the mono-devel package) ---------
monodis --output=chall.il chall.exe   # full IL disassembly
monodis --typedef chall.exe           # list types
monodis --strings chall.exe           # dump the #US heap - often just hands you the flag
ikdasm chall.exe > chall.il           # the ildasm workalike

# --- Just want the strings? -----------------------------------------------
# #US entries are UTF-16LE; plain `strings -el` finds them
strings -a -el chall.exe | less
```

## Deobfuscating

```sh
# de4dot recognises ~30 obfuscators and undoes renaming, string encryption,
# control flow and proxy calls in one pass
de4dot -f chall.exe -o clean.exe
# Just identify what protected it
de4dot --detect chall.exe
# Force a specific deobfuscator when detection fails (p = preserve tokens)
de4dot -p cr -f chall.exe -o clean.exe     # cr = ConfuserEx profile
de4dot --only-cflow-deob -f chall.exe -o clean.exe
# Keep the original names if de4dot's generated ones are worse
de4dot --keep-names ntpfmd -f chall.exe -o clean.exe
```

### ConfuserEx specifics

ConfuserEx (and its many forks) is the obfuscator you will meet in CTFs. Its layers:

| Protection | Symptom | Removal |
|---|---|---|
| Renaming | types named with invisible chars (U+0002, U+206A) | de4dot renames to `Class1`/`method_0` |
| Anti-tamper | the method bodies are encrypted; IL is garbage until runtime | dump at runtime, or use a ConfuserEx unpacker |
| Anti-debug / anti-dump | exits under dnSpy | patch the module initialiser, or use ExtremeDumper |
| Constant encryption | every literal is `Class1.smethod_0(1234)` | invoke the decryptor reflectively (below) |
| Control-flow obfuscation | switch-based flattening in IL | `de4dot --only-cflow-deob` |
| Proxy calls | `call` replaced by delegate field invocation | de4dot resolves most |
| Resource protection | the real assembly is a compressed resource | dump the decompressed module at runtime |

The universal ConfuserEx answer when tooling fails: let the program run past its module
initialiser (which decrypts everything into memory), then dump the in-memory module with
**MegaDumper**/**ExtremeDumper**/**pd** (ProcessDump) and open the dump. Anti-tamper and
constant encryption are both already undone in that dump.

### String decryption by reflection

When an obfuscator replaces literals with `Decryptor.Get(0x1A2B)` and de4dot cannot handle
it, call the decryptor yourself. Build this as a small C# console app referencing the target:

```csharp
// decrypt.cs
//   csc /r:chall.exe decrypt.cs        (or: dotnet build with a project reference)
//   decrypt.exe 0 2000
using System;
using System.Reflection;

class Decrypt {
    static int Main(string[] args) {
        int lo = args.Length > 0 ? int.Parse(args[0]) : 0;
        int hi = args.Length > 1 ? int.Parse(args[1]) : 1000;

        Assembly asm = Assembly.LoadFrom("chall.exe");
        // Find the decryptor: usually a static method taking one int and returning string
        MethodInfo target = null;
        foreach (Type t in asm.GetTypes()) {
            foreach (MethodInfo m in t.GetMethods(BindingFlags.Static |
                                                  BindingFlags.Public |
                                                  BindingFlags.NonPublic)) {
                ParameterInfo[] ps = m.GetParameters();
                if (m.ReturnType == typeof(string) && ps.Length == 1 &&
                    ps[0].ParameterType == typeof(int)) {
                    target = m;
                    Console.WriteLine("[+] candidate: {0}.{1}", t.FullName, m.Name);
                }
            }
        }
        if (target == null) { Console.WriteLine("[-] no candidate found"); return 1; }

        for (int i = lo; i < hi; i++) {
            try {
                object s = target.Invoke(null, new object[] { i });
                if (s != null && ((string)s).Length > 2)
                    Console.WriteLine("{0,6}: {1}", i, s);
            } catch { /* wrong id: the decryptor throws */ }
        }
        return 0;
    }
}
```

Run it in a VM: you are executing attacker-controlled code. The same trick works from
PowerShell with `[Reflection.Assembly]::LoadFrom()` and `$m.Invoke($null, @(0x1A2B))`.

## Patching

### In dnSpy (easiest)

1. Right-click the method body -> **Edit Method (C#)**. Change the code, click **Compile**.
2. Or right-click -> **Edit IL Instructions** for surgical changes.
3. **File > Save Module...** to write a new EXE.
4. dnSpy also debugs: **Debug > Start Debugging** (or attach to a running process),
   set breakpoints in the decompiled C#, inspect locals. This is by far the fastest way to
   read a runtime-generated flag.

### By hand, in IL

The IL opcodes you actually need:

| Opcode | Bytes | Meaning |
|---|---|---|
| `nop` | `00` | do nothing (the NOP of IL) |
| `ldc.i4.0` | `16` | push int 0 (= false) |
| `ldc.i4.1` | `17` | push int 1 (= true) |
| `ldc.i4.s n` | `1F nn` | push small int |
| `ldstr "s"` | `72 <tok>` | push a #US string by token |
| `ldarg.0` | `02` | push `this` / first argument |
| `ldloc.0` | `06` | push local 0 |
| `stloc.0` | `0A` | pop into local 0 |
| `br.s n` | `2B nn` | unconditional branch |
| `brfalse.s n` | `2C nn` | branch if 0/null |
| `brtrue.s n` | `2D nn` | branch if non-zero |
| `beq.s`/`bne.un.s` | `2E`/`33` | compare-and-branch |
| `call` | `28 <tok>` | static call |
| `callvirt` | `6F <tok>` | virtual call |
| `ceq` | `FE 01` | push (a == b) |
| `ret` | `2A` | return |
| `pop` | `26` | discard the top of stack |
| `throw` | `7A` | throw the top of stack |

Standard patches:

- Invert a check: `brtrue.s` (`2D`) <-> `brfalse.s` (`2C`) - one byte, same length.
- Force a bool method to return true: replace the body with `ldc.i4.1; ret` (`17 2A`) and
  NOP the rest (`00`).
- Skip a call whose return value is unused: replace `call <tok>` (5 bytes) with five `nop`s.
- Remove a call whose value *is* used: replace with `nop nop nop nop` + a `ldc.i4.0`, keeping
  the stack balanced. **Unbalanced stacks make the CLR refuse to run the method** with an
  `InvalidProgramException` - this is the one hard rule of IL patching.

`dnlib` (the library dnSpy is built on) scripts these edits; `Mono.Cecil` is the other
option. For CTF work, dnSpy's GUI is faster than either.

## Single-file and self-contained publishes

.NET 5+ `PublishSingleFile` produces a native apphost with all the managed DLLs appended as
a bundle. The bundle manifest is located via the signature
`8b 12 02 b9 6a 61 20 38 72 7b 93 02 14 d7 a0 32 13 f5 b9 e6 ef ae 33 18 ee 3b 2d ce 24 b3 6a ae`
followed by a 64-bit offset to the header. Options:

```sh
# Just run it once and take the extracted files out of the temp dir (.NET 3.1/5 style)
DOTNET_BUNDLE_EXTRACT_TO_DIRECTORY=/tmp/extract ./chall
ls -R /tmp/extract

# .NET 6+ does not extract by default; use a community extractor, or:
# carve the DLLs with binwalk - each embedded assembly still starts with MZ
binwalk -D='pe:exe' chall
# and confirm each carved file with:
python3 isdotnet.py _chall.extracted/0.exe
```

For **Native AOT** binaries there is no IL at all - treat them as ordinary native code
(`windows-pe-reversing`). The giveaway is a large native binary with `System.` strings but
no CLR header.

## Unity

```sh
# Mono backend: the game logic is plain managed code
ls Game_Data/Managed/Assembly-CSharp.dll        # open this in dnSpy - done
# IL2CPP backend: C# was transpiled to C++ and compiled natively
ls GameAssembly.dll Game_Data/il2cpp_data/Metadata/global-metadata.dat
# Il2CppDumper reconstructs the symbol names and emits a dummy DLL + script for Ghidra/IDA
Il2CppDumper GameAssembly.dll global-metadata.dat out/
# out/ contains: DummyDll/ (open in dnSpy for structure), script.py (rename functions in
# IDA/Ghidra), stringliteral.json (all the strings)
```

## Variants & pitfalls

- **Mixed-mode assemblies** (`ILONLY` flag clear) contain native code too; the interesting
  part may be in the native half.
- **`InvalidProgramException` after a patch** = unbalanced evaluation stack or a bad token.
  Undo and patch with dnSpy's editor instead of a hex editor.
- **Strong-name signature** breaks on patching. Either remove the signature (de4dot does
  this) or disable verification; for a CTF, just run it - the CLR only verifies on
  strong-name-dependent loads.
- **Obfuscated names containing invisible Unicode** make grep useless; always run de4dot
  first so names become ASCII.
- **The flag may never be a string literal**: it can be assembled from an encrypted resource
  or computed. Use dnSpy's debugger and put a breakpoint after the construction.
- **PowerShell/`Add-Type` payloads** compile at runtime; the interesting artefact may be a
  base64 blob rather than the EXE.
- **`#-` instead of `#~`** means uncompressed metadata tables, a typical sign that the file
  was produced/edited by a tool rather than a compiler - often an obfuscator.

## Tools

- `dnSpyEx` - actively maintained dnSpy fork: decompile, edit, debug.
- `ILSpy` / `ilspycmd` / `AvaloniaILSpy` - cross-platform decompilation.
- `de4dot` (and the de4dot-cex fork for ConfuserEx) - deobfuscation.
- `dnlib` / `Mono.Cecil` - programmatic assembly rewriting.
- `monodis` / `ikdasm` - IL disassembly on Linux.
- `Il2CppDumper` - Unity IL2CPP metadata recovery.
- `ExtremeDumper` / `MegaDumper` - dump managed modules from a live process.

## References

- ECMA-335, "Common Language Infrastructure": Partition II describes the CLI header,
  metadata root, `BSJB` signature and stream layout used by the script above; Partition III
  lists every IL opcode and its byte encoding.
- dnSpy documentation for Edit Method / Save Module and the debugger.
