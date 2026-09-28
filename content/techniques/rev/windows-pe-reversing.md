---
title: "Windows PE Reversing - Imports, TLS Callbacks and x64dbg"
category: rev
subcategory: windows-pe
type: technique
tags: [windows, pe, portable-executable, imports, iat, tls-callback, resources, overlay, x64dbg, wine, winedbg, qiling, rich-header, pdb, exception-directory, api-hashing, dllmain, ordinal-imports]
difficulty: medium
summary: "Read a PE's imports, TLS callbacks, resources and overlay to find the code that matters, then drive it in x64dbg - or run it on Linux with wine or Qiling."
when_to_use:
  - "The challenge is a .exe or .dll and you want the fastest route to the check"
  - "Code runs before main and your breakpoint at the entry point is too late"
  - "The interesting payload is in a resource, an overlay, or resolved by API hashing"
  - "You are on Linux and need to run or emulate a Windows binary"
tools: [x64dbg, ghidra, ida, pefile, wine, winedbg, qiling, rabin2, wrestool, scylla]
related: [dotnet-reversing, packers-and-unpacking, anti-debug-bypass, anti-vm-bypass, shellcode-analysis, triage-unknown-binary, binary-patching]
---

## TL;DR

For a native PE, three artefacts tell you almost everything before you read a single
instruction: the **import table** (what the program can do), the **TLS callback array**
(code that runs before the entry point - the classic anti-debug hiding place), and the
**resources/overlay** (where the real payload usually lives). Then drive it in x64dbg, or
under wine/Qiling if you are on Linux.

## Recognise it and triage

```sh
# Identity and layout
file chall.exe
rabin2 -I chall.exe                  # arch, bits, subsystem, nx, pic, canary, .NET or not
rabin2 -S chall.exe                  # sections with perms and sizes
rabin2 -i chall.exe                  # imports
rabin2 -E chall.exe                  # exports (for a DLL)
rabin2 -z chall.exe                  # strings in data sections
rabin2 -zz chall.exe | grep -i http  # strings everywhere, including headers

# Resources and overlay
wrestool -l chall.exe                # list resources (icoutils package)
wrestool -x -t 10 -o out/ chall.exe  # extract RCDATA (type 10) - payloads hide here
binwalk chall.exe                    # finds appended archives/PEs in the overlay

# Quick capability triage
capa -v chall.exe                    # maps behaviours to rules: "encrypt data using AES"
```

## The import table

The IAT is the single most informative structure in a PE. Each imported DLL has an
`IMAGE_IMPORT_DESCRIPTOR` pointing at two parallel arrays: the **ILT** (names/ordinals, read
only) and the **IAT** (patched by the loader with real addresses at load time).

| Import you see | What it implies |
|---|---|
| `CreateFileW`, `ReadFile`, `WriteFile` | file I/O - the flag may be read from or written to disk |
| `VirtualAlloc` + `VirtualProtect` + `memcpy` | self-modifying / unpacking / shellcode |
| `WriteProcessMemory`, `CreateRemoteThread`, `NtMapViewOfSection` | process injection |
| `CryptAcquireContext`, `CryptDeriveKey`, `CryptDecrypt` | CryptoAPI - the key derivation is nearby |
| `BCryptGenerateSymmetricKey`, `BCryptDecrypt` | CNG (modern equivalent) |
| `RegOpenKeyExA`, `RegQueryValueEx` | registry-driven config or anti-VM (see `anti-vm-bypass`) |
| `InternetOpenUrlA`, `WinHttpConnect`, `send`/`recv` | network - look for the C2/flag server |
| `IsDebuggerPresent`, `NtQueryInformationProcess` | anti-debug (see `anti-debug-bypass`) |
| `GetProcAddress` + `LoadLibraryA` only | dynamic resolution - the real imports are hidden |
| `GetModuleHandleA` with no imports at all | API hashing - see below |
| `SetUnhandledExceptionFilter`, `AddVectoredExceptionHandler` | exception-driven control flow |
| `mscoree.dll!_CorExeMain` | managed - go to `dotnet-reversing` |

**Ordinal-only imports** appear as `WS2_32.dll!#115` (that is `recv`). Look the ordinal up in
the exporting DLL: `rabin2 -E C:/Windows/System32/ws2_32.dll` or an online ordinal table.
Ghidra resolves these automatically if the DLL is in its known-ordinal database.

**Delay-load imports** (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`, index 13) are resolved on first
use, not at load. A function may appear unimported yet still be called.

**API hashing**: no meaningful imports, plus a loop over a module's export table comparing a
computed hash to a constant. Very common in shellcode-style loaders. See `shellcode-analysis`
for the ROR13 hash table used to resolve those constants back to API names.

## TLS callbacks - code that runs before the entry point

`IMAGE_DIRECTORY_ENTRY_TLS` (index 9) points to an `IMAGE_TLS_DIRECTORY` whose
`AddressOfCallBacks` field is a NULL-terminated array of function pointers. Every callback
runs on process attach - **before** `AddressOfEntryPoint` - and again on thread attach.
This is where anti-debug checks and unpacking stubs hide.

```sh
# Find them statically
rabin2 -I chall.exe | grep -i tls
python3 pedump.py chall.exe | grep -A5 'TLS'      # script below
```

In **x64dbg**: Options -> Preferences -> Events -> tick **TLS Callbacks** (and "System
Breakpoint"), then restart the debuggee. The debugger now stops in each callback before the
entry point. In **Ghidra**, the TLS callbacks appear in the Symbol Tree under "Exports" or
as `tls_callback_0`; if not, navigate to the address from the data directory and press `F`
to create a function.

```c
/* what a TLS callback looks like in source */
void NTAPI tls_callback(PVOID handle, DWORD reason, PVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH && IsDebuggerPresent())
        ExitProcess(0);                 /* your breakpoint at main never gets hit */
}
#pragma comment(linker, "/INCLUDE:__tls_used")
```

## Code - parse a PE with the stdlib only

```python
#!/usr/bin/env python3
"""pedump.py - sections, imports, exports, TLS callbacks and overlay of a PE.

No pefile dependency (though pefile is nicer if you have it - see the note at the end).

Usage: python3 pedump.py chall.exe
"""
import struct
import sys

DIRS = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG",
        "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT",
        "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"]
MACHINE = {0x014C: "i386", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64",
           0x01C4: "ARMNT", 0x0200: "IA64"}
SUBSYSTEM = {1: "native", 2: "GUI", 3: "console", 9: "WinCE", 10: "EFI application"}
CHARS = [(0x20000000, "EXEC"), (0x40000000, "READ"), (0x80000000, "WRITE"),
         (0x00000020, "CODE"), (0x00000040, "IDATA"), (0x00000080, "UDATA")]


class PE:
    def __init__(self, path: str):
        with open(path, "rb") as fh:
            self.data = fh.read()
        if self.data[:2] != b"MZ":
            raise ValueError("not a PE (no MZ)")
        self.pe_off = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[self.pe_off:self.pe_off + 4] != b"PE\0\0":
            raise ValueError("not a PE (no PE\\0\\0)")
        self.machine, self.n_sections = struct.unpack_from("<HH", self.data, self.pe_off + 4)
        self.opt_size = struct.unpack_from("<H", self.data, self.pe_off + 20)[0]
        self.opt = self.pe_off + 24
        self.magic = struct.unpack_from("<H", self.data, self.opt)[0]
        self.plus = self.magic == 0x20B
        self.entry = struct.unpack_from("<I", self.data, self.opt + 16)[0]
        if self.plus:
            self.image_base = struct.unpack_from("<Q", self.data, self.opt + 24)[0]
            dd = self.opt + 112
        else:
            self.image_base = struct.unpack_from("<I", self.data, self.opt + 28)[0]
            dd = self.opt + 96
        self.subsystem = struct.unpack_from("<H", self.data, self.opt + 68)[0]
        self.dirs = [struct.unpack_from("<II", self.data, dd + i * 8) for i in range(16)]
        self.sections = []
        sec = self.opt + self.opt_size
        for i in range(self.n_sections):
            base = sec + i * 40
            name = self.data[base:base + 8].rstrip(b"\0").decode(errors="replace")
            vsize, va, rsize, raw, _, _, _, chars = struct.unpack_from("<IIIIIIHI",
                                                                      self.data, base + 8)
            self.sections.append({"name": name, "va": va, "vsize": vsize,
                                  "raw": raw, "rsize": rsize, "chars": chars})

    def off(self, rva: int) -> int | None:
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                delta = rva - s["va"]
                return s["raw"] + delta if delta < s["rsize"] else None
        return None

    def cstr(self, rva: int) -> str:
        o = self.off(rva)
        if o is None:
            return "<unmapped>"
        end = self.data.index(b"\0", o)
        return self.data[o:end].decode(errors="replace")


def show(pe: PE) -> None:
    print(f"[*] {MACHINE.get(pe.machine, hex(pe.machine))} PE{'32+' if pe.plus else '32'}, "
          f"subsystem={SUBSYSTEM.get(pe.subsystem, pe.subsystem)}")
    print(f"    image base {pe.image_base:#x}, entry rva {pe.entry:#x} "
          f"(va {pe.image_base + pe.entry:#x})")

    print("\n[*] sections")
    for s in pe.sections:
        flags = "|".join(n for bit, n in CHARS if s["chars"] & bit)
        warn = "  <-- W+X!" if (s["chars"] & 0x20000000 and s["chars"] & 0x80000000) else ""
        print(f"    {s['name']:<9} va={s['va']:#010x} vsize={s['vsize']:#x} "
              f"raw={s['raw']:#x} rsize={s['rsize']:#x} {flags}{warn}")

    print("\n[*] data directories")
    for i, (rva, size) in enumerate(pe.dirs):
        if rva:
            print(f"    {DIRS[i]:<15} rva={rva:#010x} size={size:#x}")

    # --- imports ---------------------------------------------------------
    imp_rva, _ = pe.dirs[1]
    if imp_rva:
        print("\n[*] imports")
        o = pe.off(imp_rva)
        while o is not None:
            ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", pe.data, o)
            if name_rva == 0:
                break
            print(f"    {pe.cstr(name_rva)}")
            thunk_rva = ilt or iat
            t = pe.off(thunk_rva)
            width = 8 if pe.plus else 4
            fmt = "<Q" if pe.plus else "<I"
            high = 1 << (63 if pe.plus else 31)
            while t is not None:
                (entry,) = struct.unpack_from(fmt, pe.data, t)
                if entry == 0:
                    break
                if entry & high:
                    print(f"        #{entry & 0xFFFF}   (ordinal)")
                else:
                    hint_off = pe.off(entry & 0x7FFFFFFF)
                    if hint_off is not None:
                        end = pe.data.index(b"\0", hint_off + 2)
                        print(f"        {pe.data[hint_off + 2:end].decode(errors='replace')}")
                t += width
            o += 20

    # --- exports ---------------------------------------------------------
    exp_rva, _ = pe.dirs[0]
    if exp_rva:
        o = pe.off(exp_rva)
        if o is not None:
            n_names, names_rva, ords_rva = struct.unpack_from("<III", pe.data, o + 24)
            base_ord = struct.unpack_from("<I", pe.data, o + 16)[0]
            print(f"\n[*] exports ({n_names} named)")
            no = pe.off(names_rva)
            oo = pe.off(ords_rva)
            for i in range(min(n_names, 200)):
                (nrva,) = struct.unpack_from("<I", pe.data, no + i * 4)
                (ordinal,) = struct.unpack_from("<H", pe.data, oo + i * 2)
                print(f"    #{ordinal + base_ord:<5} {pe.cstr(nrva)}")

    # --- TLS callbacks ---------------------------------------------------
    tls_rva, _ = pe.dirs[9]
    if tls_rva:
        o = pe.off(tls_rva)
        if o is not None:
            fmt = "<QQQQ" if pe.plus else "<IIII"
            size = 32 if pe.plus else 16
            _start, _end, _index, cbs = struct.unpack_from(fmt, pe.data, o)
            print(f"\n[!] TLS directory present; AddressOfCallBacks = {cbs:#x}")
            co = pe.off(cbs - pe.image_base)
            ptr_fmt = "<Q" if pe.plus else "<I"
            width = 8 if pe.plus else 4
            idx = 0
            while co is not None and idx < 16:
                (fn,) = struct.unpack_from(ptr_fmt, pe.data, co)
                if fn == 0:
                    break
                print(f"    callback[{idx}] = {fn:#x} (rva {fn - pe.image_base:#x})"
                      "  <-- runs BEFORE the entry point")
                co += width
                idx += 1
            _ = size

    # --- overlay ---------------------------------------------------------
    end_of_image = max(s["raw"] + s["rsize"] for s in pe.sections)
    if len(pe.data) > end_of_image:
        extra = len(pe.data) - end_of_image
        print(f"\n[!] overlay: {extra} bytes past the last section at {end_of_image:#x}")
        head = pe.data[end_of_image:end_of_image + 8]
        print(f"    first bytes: {head.hex(' ')}  {head!r}")
        print("    try: binwalk -e, or dd bs=1 skip=... to carve it")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pedump.py <file.exe|file.dll>")
        return 1
    try:
        show(PE(sys.argv[1]))
    except ValueError as exc:
        print(f"[-] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

With `pefile` installed the same information is one call away
(`pe = pefile.PE(path); pe.print_info()`, `pe.DIRECTORY_ENTRY_IMPORT`,
`pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks`), and `pe.get_offset_from_rva(rva)` is
the address translation you need for patching.

## Resources and overlay

```sh
# Resource types: 1 cursor, 2 bitmap, 3 icon, 4 menu, 5 dialog, 6 string table,
#                 10 RCDATA (arbitrary data - the usual payload hiding place),
#                 16 version info, 24 manifest
wrestool -l chall.exe
wrestool -x -t 10 -o extracted/ chall.exe
# Ghidra: Window > "Resource Viewer" (after the PE loader ran)
# Anything appended after the last section is the "overlay" - installers, zips, payloads
binwalk -e chall.exe
```

## x64dbg workflow

```
; --- Breakpoints ---------------------------------------------------------
bp VirtualAlloc              ; software breakpoint on an export by name
bph 0x140001234, x, 1        ; hardware exec breakpoint (invisible to 0xCC scans)
bpm 0x00405000, 0, a         ; memory breakpoint: break on any access to a page
bp CreateFileW, "arg.get(0)" ; log a value without stopping (use a logging condition)

; --- Useful commands ------------------------------------------------------
run                          ; F9
StepInto / StepOver          ; F7 / F8
rtu                          ; "Run to user code" - skip system DLL noise
dump rax                     ; show memory at a register in the dump pane
find 0, "CTF{"               ; search the whole module for a pattern
findallmem 0, "flag"         ; search all memory
```

GUI features that matter:

- **Options -> Preferences -> Events**: enable *TLS Callbacks*, *DLL Entry*, *System
  Breakpoint* so nothing runs before you see it.
- **Breakpoints tab** -> right-click a breakpoint -> *Edit* -> set a **log text** like
  `{s:[rcx]}` and tick *Log* + untick *Break* to build a trace without stopping.
- **Trace -> Trace record / Run trace** to record executed instructions; then
  *Trace coverage* highlights what ran.
- **Follow in Dump** on any pointer; the dump pane has an ASCII view that usually shows the
  flag.
- **Symbols tab**: load PDBs (public Microsoft symbols) so `ntdll` calls are named.
- Plugins: **Scylla** (dump + rebuild IAT, see `packers-and-unpacking`), **ScyllaHide**
  (anti-anti-debug, see `anti-debug-bypass`), **xAnalyzer** (API argument annotation).

## Structures worth knowing

- **Rich header**: undocumented block between the DOS stub and the PE header listing the
  compiler/linker build numbers of every object file. `pefile`'s `get_rich_header_hash()`
  or `rich_header` give you a toolchain fingerprint - useful for grouping samples and for
  detecting that a binary was *not* built by the compiler it claims.
- **Exception directory (`.pdata`)** on x64: an array of `RUNTIME_FUNCTION`
  `{BeginAddress, EndAddress, UnwindInfoAddress}`. It gives exact function boundaries for
  free, which is gold in a stripped binary. Ghidra uses it automatically; you can also read
  it with the script above (data directory index 3).
- **Relocations (`.reloc`)**: needed when `/DYNAMICBASE` is set. If you rebase a dump you
  must apply them or absolute addresses will be wrong.
- **`.pdb` path**: often left in the Debug directory - `strings -a chall.exe | grep -i '\.pdb'`
  reveals the original project path, user name and sometimes the intended solution's
  function names.

## Running Windows binaries on Linux

```sh
# wine: usually enough for a console CTF binary
wine chall.exe
WINEDEBUG=+relay wine chall.exe 2>&1 | head -100     # log every API call - very powerful
WINEDEBUG=+snoop,+relay wine chall.exe 2>&1 | grep -i crypt

# winedbg: a gdb-like debugger for wine processes
winedbg chall.exe
winedbg --gdb chall.exe        # then use gdb commands
# (winedbg) break *0x401000 / cont / info registers / x/16xb 0x402000

# Qiling: emulate the PE with a fake Windows rootfs - no wine, full control
python3 - <<'PY'
from qiling import Qiling
ql = Qiling([r"chall.exe"], r"examples/rootfs/x8664_windows", verbose=4)
ql.run()
PY
```

Qiling is the right choice when the binary refuses to run under wine, when you want to hook
specific APIs (`ql.os.set_api("CreateFileW", my_hook)`), or when you need determinism. See
`unicorn-qiling-emulation`.

## Variants & pitfalls

- **DLL, not EXE**: run it with `rundll32 chall.dll,ExportedFunction`, or write a tiny
  loader, or use `regsvr32` for COM DLLs. In x64dbg, use *File -> Open* on the DLL; it loads
  a stub host. Check `DllMain` (called before any export you invoke).
- **`AddressOfEntryPoint` is not `main`**: the CRT startup (`__scrt_common_main_seh`) runs
  first. Find `main` by following the call to `invoke_main`, or by looking for the call
  taking `argc`/`argv`/`envp`.
- **Static CRT bloats the binary** with thousands of library functions. Apply FLIRT (IDA) or
  Ghidra's Function ID to filter them out; otherwise you will read `printf` internals for an
  hour.
- **`.rsrc` payload extraction fails** if the resource is compressed or encrypted - check
  entropy, then find the decompression call.
- **Checksum/signature**: patching invalidates both. Windows only enforces the Authenticode
  signature for drivers and some protected processes - a normal patched EXE still runs.
- **Anti-debug in `DllMain`/TLS** - enable those debugger events first (see above).
- **32-bit vs 64-bit** matters for tooling: use the matching x32dbg/x64dbg binary.
- **Managed vs native**: always check the COM descriptor directory first
  (`dotnet-reversing`), it saves hours.

## Tools

- `x64dbg`/`x32dbg` + ScyllaHide + Scylla - the standard Windows debugger stack.
- `Ghidra` / `IDA` / `Binary Ninja` - static analysis, all handle PE and `.pdata`.
- `pefile` (Python), `rabin2`, `dumpbin /imports /exports /headers` (MSVC) - header parsing.
- `wrestool` / `icoutils`, `Resource Hacker` - resources.
- `capa` - behaviour identification from imports and code patterns.
- `wine` + `WINEDEBUG=+relay`, `winedbg`, `Qiling` - run it without Windows.
- `PE-bear` / `CFF Explorer` / `Detect It Easy` - GUI header inspection and editing.

## References

- Microsoft PE Format specification (data directory indices, IMAGE_TLS_DIRECTORY,
  IMAGE_IMPORT_DESCRIPTOR, RUNTIME_FUNCTION).
- x64dbg documentation: command reference and breakpoint types.
- Wine documentation for `WINEDEBUG` channels (`relay`, `snoop`).
