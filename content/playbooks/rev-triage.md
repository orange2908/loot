---
title: "Playbook - Reverse Engineering Triage"
category: rev
subcategory: triage
type: playbook
tags: [rev-triage, where-to-start, stuck, what-language, reverse-engineering, ghidra, ida, radare2, angr, decompiler, dotnet, golang, rust, python-bytecode, pyinstaller, upx, packed, obfuscation, anti-debug, vm-obfuscation]
summary: "Identify the language/toolchain of a binary, pick the right decompiler, then pick the solving strategy (read, emulate, symbolic, brute)."
when_to_use:
  - "You have a binary to reverse and do not know what produced it"
  - "The decompiler output is unreadable and you need a different approach"
  - "You need to decide between reading the code and throwing angr/z3 at it"
related: [unknown-file, ghidra, radare2, angr, z3, jadx, pwn-triage]
---

## TL;DR

```sh
file ./chal
strings -a ./chal | head -60
strings -a ./chal | grep -aiE 'go1\.|rustc|GCC:|clang|\.NET|mscorlib|python3|PyInstaller|UPX!|Qt|v8|wasm'
nm -C ./chal 2>/dev/null | head -40
```
The language determines everything. Find it in section 1, then go to the matching row.

---

## Section 1 - Language / toolchain identification

| Signal | Language | Toolchain |
|---|---|---|
| `GCC: (GNU) x.y.z` in strings, small binary, libc imports | C | Ghidra / IDA / Binary Ninja. Decompiles cleanly. |
| C++ mangled names `_ZN...`, `std::`, `__cxa_throw`, vtables | C++ | Ghidra + `c++filt`; expect vtable dispatch and RTTI. Use `nm -C`. |
| `go1.21.x`, `runtime.main`, huge (2MB+) static binary, `.gopclntab` | Go | Ghidra + GoReSym / redress; IDA + golang_loader_assist. Strings are length-prefixed, not null-terminated. |
| `rustc`, `core::panicking`, `/rustc/<hash>/library/`, `RUST_BACKTRACE` | Rust | Ghidra; look for `panic` call sites - they carry the source file/line and often the check being performed. |
| `mscorlib`, `.NET Framework`, `BSJB` magic in the file | C# / .NET | **dnSpy** or **ILSpy** or **dotPeek** - full source recovery. `ilspycmd -p -o out/ chal.exe` |
| `MonoBleedingEdge`, `Assembly-CSharp.dll`, `il2cpp` | Unity | Managed: dnSpy on `Assembly-CSharp.dll`. IL2CPP: `Il2CppDumper` + `global-metadata.dat`. |
| `Java class` / `PK` with `.class` entries / `META-INF/MANIFEST.MF` | Java | **jd-gui**, `procyon`, `cfr`, `fernflower`. `cfr chal.jar --outputdir out/` |
| `classes.dex`, `AndroidManifest.xml` | Android | **jadx**: `jadx -d out/ app.apk`. `ctfbrain search jadx` |
| `PyInstaller`, `_MEIPASS`, `python3X.dll` | Python frozen | `pyinstxtractor.py chal.exe`, then decompile the `.pyc` |
| `.pyc` magic (`\x6f\x0d\x0d\x0a` etc) | Python bytecode | `decompyle3` / `uncompyle6` (<=3.8), `pycdc` (any version), else `dis` by hand |
| `#!/usr/bin/env python` + base64 blob | Python obfuscation | unwrap the `exec(...)` layers by replacing `exec` with `print` |
| `\x00asm` (`0061736d`) | WebAssembly | `wasm2wat chal.wasm -o chal.wat`; `wabt`, or Ghidra with the wasm loader |
| Minified JS, `_0x` identifiers | JS obfuscation | `js-beautify`, de4js, then rewrite the string-array decoder in Node |
| `Electron`, `app.asar` | Electron | `npx asar extract app.asar out/` |
| `UPX!` at the end/start | packed | `upx -d chal`; if the header is corrupted, dump from memory at OEP |
| High entropy `.text`, tiny import table (`LoadLibrary`,`GetProcAddress` only) | custom packer | run under a debugger, break on `VirtualProtect`/`mprotect`, dump at OEP |
| `Nim`, `nimble`, `NimMain` | Nim | Ghidra; symbols are usually intact |
| `zig`, `std.builtin` | Zig | Ghidra |
| `LLVM`, `swift_`, `$s` mangling | Swift | `swift demangle`; Ghidra + Swift plugin |
| `Delphi`, `Borland`, `TForm` | Delphi | IDR (Interactive Delphi Reconstructor), IDA + Delphi signatures |
| `AutoIt` / `AU3!` | AutoIt | `Exe2Aut` / `myAut2Exe` |
| `Lua` / `\x1bLua` | Lua bytecode | `luadec`, `unluac` |
| `.vbs`, `.ps1`, `.bat` heavily obfuscated | script | deobfuscate by replacing the final `Invoke-Expression`/`eval` with an echo |
| `ELF` with only `syscall` and no libc | hand-written asm / shellcode | `objdump -d`, or `ndisasm -b 64` |
| A raw blob that `file` calls "data" but disassembles cleanly | shellcode | `sctest`/`scdbg`, or `objdump -D -b binary -m i386:x86-64` |

---

## Section 2 - Pick the toolchain

| Situation | Tool | Command |
|---|---|---|
| Any ELF/PE/Mach-O, first look | Ghidra | `analyzeHeadless /tmp/proj p -import ./chal -postScript X.py` ; `ctfbrain search ghidra` |
| Quick CLI triage, scripting | radare2 / rizin | `r2 -AA ./chal` then `afl`, `pdf @ main`, `iz`, `izz` |
| Best decompiler output | IDA Pro / Binary Ninja | if available |
| .NET | dnSpy / ILSpy / AvaloniaILSpy | full C# recovery, and dnSpy can patch and re-save |
| Java / Android | jadx, cfr, procyon | `jadx-gui app.apk` |
| Python bytecode | pycdc, decompyle3 | `pycdc chal.pyc > chal.py` |
| Dynamic behaviour | ltrace/strace/frida | `ltrace ./chal`, `strace -f -e trace=openat,read,write ./chal` |
| Debugging | gdb + pwndbg/gef | `ctfbrain search gdb-pwndbg-gef` |
| Constraint solving | angr / z3 | sections 4 and 5 |
| Comparing two binaries | bindiff / diaphora / radiff2 | `radiff2 -C a b` |
| Instrumenting a running app | Frida | `ctfbrain search frida` |

---

## Section 3 - Solving strategy decision tree

```
What does the binary DO with your input?
 |
 |-- Prints the flag after a single equality check on a hardcoded string
 |     -> the string IS the flag (or is one xor away). `strings`, then read the check.
 |
 |-- Compares your input to a transformed constant (xor/add/rot per byte)
 |     -> invert the transform. Write the inverse in Python. 5 minutes.
 |
 |-- Runs an independent check per character (input[i] op k == c[i])
 |     -> brute force each byte independently: 256 * len tries.
 |
 |-- Runs checks that couple characters (sums, products, a matrix, a CRC)
 |     -> z3. `ctfbrain search z3`
 |
 |-- Has a big branching maze / many nested conditions and a 'win' printf
 |     -> angr with find=<win addr>, avoid=<fail addr>. `ctfbrain search angr`
 |
 |-- Implements a known crypto primitive (AES/RC4/TEA/XTEA/base64 variant)
 |     -> identify by constants (see the table below), then decrypt offline.
 |
 |-- Implements a custom VM (a fetch-decode-execute loop over a byte array)
 |     -> write a disassembler for the VM's opcode table, then read the bytecode as a program.
 |        `ctfbrain search vm-obfuscation`
 |
 |-- Checks the flag against a hash
 |     -> hashcat with a mask, or z3 if the hash is a weak custom one.
 |
 |-- Does nothing visible / exits immediately
 |     -> anti-debug or an environment check. strace it, patch the check.
 |
 |-- Is huge and the flag check is buried
 |     -> find the success string, xref it backwards to the check.
```

### Magic constants that identify an algorithm instantly

| Constant | Algorithm |
|---|---|
| `0x9E3779B9` | TEA / XTEA / XXTEA (delta), also used in hashes |
| `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476` | MD5 / MD4 / SHA-1 init |
| `0x6A09E667 0xBB67AE85` | SHA-256 init |
| `0x428A2F98` (start of a 64-entry table) | SHA-256 round constants |
| `0x63 0x7C 0x77 0x7B 0xF2 0x6B 0x6F 0xC5` | AES S-box |
| `0x52 0x09 0x6A 0xD5` | AES inverse S-box |
| `0xEDB88320` | CRC32 (reflected polynomial) |
| `0x04C11DB7` | CRC32 (normal) |
| `0x243F6A88` (pi digits) | Blowfish P-array |
| A 256-byte identity array being shuffled | RC4 KSA |
| `0x61707865 0x3320646e 0x79622d32 0x6b206574` ("expand 32-byte k") | ChaCha20 / Salsa20 |
| `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | base64 (check for a modified alphabet!) |
| `0x5A827999 0x6ED9EBA1 0x8F1BBCDC 0xCA62C1D6` | SHA-1 round constants |
| `0x0000000100000000` style 64-bit deltas | a custom LCG |

---

## Section 4 - When to use angr

Use angr when the path to "win" is a **branch maze** with a bounded input length and no heavy crypto/hashing along the way.

```python
#!/usr/bin/env python3
import angr, claripy, sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "./chal"
FLAG_LEN = 32

proj = angr.Project(BIN, auto_load_libs=False)
flag = claripy.BVS("flag", FLAG_LEN * 8)
state = proj.factory.full_init_state(
    args=[BIN],
    stdin=flag,
    add_options=angr.options.unicorn | {angr.options.LAZY_SOLVES},
)
# constrain to printable so the solver does not wander
for i in range(FLAG_LEN):
    b = flag.get_byte(i)
    state.solver.add(claripy.Or(b == 0x0a, claripy.And(b >= 0x20, b <= 0x7e)))

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),
    avoid=lambda s: b"Wrong" in s.posix.dumps(1),
)
if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
else:
    print("no solution - try explicit find/avoid addresses, or hook the heavy function")
```

**angr will NOT work** when: the input length is unknown and large, the program hashes the input (SHA/MD5), there is a loop with a symbolic bound, or there are thousands of paths (state explosion). Then: hook the expensive function (`proj.hook(addr, hook_fn)`), or switch to z3 on the extracted constraints.

`ctfbrain search angr`

---

## Section 5 - When to use z3

Use z3 when you can **read the check** and express it as equations, even if it is ugly. This is faster and far more reliable than angr.

```python
#!/usr/bin/env python3
from z3 import BitVec, Solver, sat, Concat

N = 20
s = Solver()
flag = [BitVec(f"c{i}", 8) for i in range(N)]
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# transcribe the binary's checks here, e.g.:
# s.add(flag[0] ^ flag[1] == 0x15)
# s.add(flag[2] + flag[3] * 3 == 0x1f4)
s.add(flag[0] == ord("f"), flag[1] == ord("l"), flag[2] == ord("a"), flag[3] == ord("g"))

if s.check() == sat:
    m = s.model()
    print(bytes(m[c].as_long() for c in flag))
else:
    print("unsat - your transcription is wrong or the constraints conflict")
```
Remember: z3 `BitVec` arithmetic is modular and matches C semantics; use `LShR` for unsigned right shift (`>>` on a BitVec is arithmetic).

`ctfbrain search z3`

---

## Section 6 - Anti-debug and anti-analysis

| Check | Bypass |
|---|---|
| `ptrace(PTRACE_TRACEME)` returns -1 under a debugger | patch the call to `xor eax,eax`, or `LD_PRELOAD` a fake `ptrace` |
| `/proc/self/status` `TracerPid` | patch the comparison |
| `IsDebuggerPresent` / `PEB->BeingDebugged` | patch, or use ScyllaHide |
| Timing checks (`rdtsc`, `clock_gettime`) | patch the delta comparison; do not single-step through it |
| `int3` / `0xCC` scanning of its own code | use hardware breakpoints only |
| Signal handlers used for control flow (SIGSEGV/SIGTRAP) | `handle SIGSEGV nostop noprint pass` in gdb |
| Checksum of its own `.text` | patch after the check, or in memory |
| `fork()` + the child debugs the parent | `set follow-fork-mode child`, `set detach-on-fork off` |
| Environment/argv[0] checks | run it exactly as intended |
| VM/sandbox detection (CPUID hypervisor bit, MAC prefixes) | patch |

LD_PRELOAD stub to neuter ptrace:
```c
/* gcc -shared -fPIC -o noptrace.so noptrace.c ; LD_PRELOAD=./noptrace.so gdb ./chal */
#include <stdio.h>
long ptrace(int request, int pid, void *addr, void *data) { return 0; }
```

---

## Section 7 - Fast wins to try before deep reversing

```sh
# 1. the flag is just there
strings -a -n 6 ./chal | grep -iE 'flag|ctf\{|key|pass'
# 2. the flag is xored with a single byte
python3 -c "
d=open('./chal','rb').read()
for k in range(1,256):
    x=bytes(b^k for b in d)
    if b'flag{' in x.lower() or b'ctf{' in x.lower(): print(k, x[x.lower().find(b'lag{')-1:][:60])"
# 3. the comparison is done with strcmp -> ltrace shows the expected value
ltrace -s 200 ./chal <<< 'AAAAAAAAAAAAAAAA' 2>&1 | grep -iE 'strcmp|strncmp|memcmp'
# 4. the flag is built on the stack -> break on the compare and read memory
gdb -q ./chal -ex 'b strcmp' -ex 'r' -ex 'x/s $rsi'
# 5. the binary reads a file -> strace names it
strace -f -e trace=openat,read ./chal 2>&1 | grep -v ENOENT
# 6. the check is a single conditional jump -> patch it and run
#    (find it in Ghidra, then:)  printf '\x90\x90' | dd of=chal bs=1 seek=<offset> conv=notrunc
```

If none of this works after 30 minutes: `ctfbrain search stuck`
