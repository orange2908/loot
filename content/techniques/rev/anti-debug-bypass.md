---
title: "Anti-Debugging - Every Trick and How to Defeat It"
category: rev
subcategory: anti-debug
type: technique
tags: [anti-debug, antidebug, ptrace, tracerpid, proc-self-status, rdtsc, timing-check, int3, sigtrap, ld-preload, gdb, isdebuggerpresent, peb, ntqueryinformationprocess, scyllahide, nt-global-flag, hardware-breakpoints, self-debugging]
difficulty: medium
summary: "ptrace self-attach, TracerPid, rdtsc deltas, int3 handlers and the Windows PEB checks - what each looks like in the disassembly and the fastest bypass for each."
when_to_use:
  - "The binary runs fine standalone but exits, crashes or prints 'nope' under gdb/x64dbg"
  - "You see ptrace, /proc/self/status, rdtsc, IsDebuggerPresent or NtQueryInformationProcess in the imports"
  - "Breakpoints cause the program to take a different path"
  - "You need to attach a dynamic tool (frida, ltrace, PIN) to an uncooperative target"
tools: [gdb, ltrace, ld-preload, x64dbg, scyllahide, radare2, ghidra, frida]
related: [anti-vm-bypass, binary-patching, dynamic-analysis-ltrace-ldpreload, packers-and-unpacking, windows-pe-reversing]
---

## TL;DR

Anti-debugging is a set of environment probes. Every one of them is defeated by one of four
moves: patch the check out of the binary, lie to it from a preloaded library, lie to it from
the debugger (set the return value after the call), or run it under an emulator that the
check cannot see. Find them by grepping the imports and the strings; they are rarely hidden.

## Recognise it

```sh
# The imports give away most Linux anti-debug in one command
nm -D ./chall | grep -Ei 'ptrace|fork|personality|prctl|signal|sigaction|clock_gettime'
# Strings give away the /proc probes
strings -a ./chall | grep -E '/proc/self/(status|cmdline|maps)|TracerPid|/proc/[0-9]'
# rdtsc / cpuid / int3 appear as raw instructions, not imports
objdump -d ./chall | grep -nE '\b(rdtsc|rdtscp|cpuid|int3|int \$0x3)\b'
# Windows PE
rabin2 -i chall.exe | grep -Ei 'IsDebuggerPresent|CheckRemote|NtQuery|OutputDebugString|NtSetInformationThread'
```

Behavioural tells: works standalone but not under gdb; different output when a breakpoint is
set; process exits with a strange code; `ltrace` shows `ptrace(PTRACE_TRACEME) = -1`.

## Linux checks

### 1. ptrace(PTRACE_TRACEME) self-attach

A process may only be traced by one tracer. If the program traces itself first, gdb cannot
attach; if gdb is already attached, `PTRACE_TRACEME` returns -1.

```c
#include <sys/ptrace.h>
#include <stdlib.h>
int main(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {  /* -1 => a debugger is attached */
        puts("debugger detected");
        exit(1);
    }
    /* real code */
}
```

In the disassembly: `mov edi, 0; call ptrace@plt; test rax, rax; js .Lfail` - or a raw
`mov eax, 101; syscall` if statically linked (101 = `__NR_ptrace` on x86-64).

Bypasses, cheapest first:

```sh
# (a) Preload a fake ptrace that always succeeds (works for dynamically linked binaries)
LD_PRELOAD=./noptrace.so ./chall

# (b) In gdb: catch the syscall and force the return value to 0
gdb -q ./chall
# (gdb) catch syscall ptrace
# (gdb) run
# (gdb) set $rax = 0
# (gdb) continue
# ... or, once and for all:
# (gdb) catch syscall ptrace
# (gdb) commands
# >silent
# >set $rax = 0
# >continue
# >end

# (c) NOP the call in the binary (5 bytes for a PLT call)
r2 -w -q -c 's sym.imp.ptrace; af; axt' ./chall      # find the callers first

# (d) LD_PRELOAD is often checked - use a gdb breakpoint on the PLT stub instead
gdb -q -ex 'break *ptrace' -ex 'run' -ex 'return 0' -ex 'continue' ./chall
```

### 2. /proc/self/status TracerPid

```c
int traced(void) {
    char buf[4096]; FILE *f = fopen("/proc/self/status", "r");
    size_t n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0; fclose(f);
    char *p = strstr(buf, "TracerPid:");
    return p && atoi(p + 10) != 0;
}
```

In the disassembly: a string `"/proc/self/status"` or `"TracerPid"` in `.rodata`, `fopen`,
`strstr`, `atoi`. Bypasses: preload a hooked `open`/`fopen` that redirects the path to a
doctored file (shim below); or bind-mount a fake file into the mount namespace:

```sh
# Create a fake status file with TracerPid: 0 and bind-mount it over the real one
sed 's/^TracerPid:.*/TracerPid:\t0/' /proc/self/status > /tmp/fake_status
# A private mount namespace so you do not disturb the host
unshare -m --map-root-user sh -c 'mount --bind /tmp/fake_status /proc/self/status; ./chall'
# Simplest of all: break on strstr/atoi and change the result
gdb -q -ex 'break atoi' -ex 'run' -ex 'return 0' ./chall
```

### 3. Parent process name

```c
/* if the parent is gdb / strace / ltrace, bail */
char path[64], comm[64];
snprintf(path, sizeof path, "/proc/%d/comm", getppid());
/* read comm, strcmp against "gdb" */
```

Bypass: run the target from a shell with `setsid ./chall &` and attach afterwards with
`gdb -p <pid>`, so the parent is `bash`, not `gdb`. Or hook `getppid` to return 1.

### 4. rdtsc / clock_gettime timing deltas

```c
unsigned long long t1 = __rdtsc();
/* a few instructions that a human would single-step through */
unsigned long long t2 = __rdtsc();
if (t2 - t1 > 100000) { puts("too slow - debugger"); exit(1); }
```

Signal: `rdtsc` (`0f 31`) or `rdtscp` (`0f 01 f9`) appearing twice close together, a
subtraction, and a comparison against a large constant. Bypasses:

```sh
# Patch the comparison (easiest): invert the jump or NOP the whole block
# Or, in gdb, zero the high/low halves after each rdtsc:
gdb -q ./chall
# (gdb) break *0x401234        # the second rdtsc
# (gdb) commands
# >silent
# >set $rax = 0
# >set $rdx = 0
# >continue
# >end
```

`clock_gettime`/`gettimeofday` versions are even easier: `LD_PRELOAD` a stub returning a
frozen time. Under qemu-user or Unicorn, `rdtsc` can be hooked directly
(`UC_HOOK_INSN`, `UC_X86_INS_RDTSC`).

### 5. int3 / SIGTRAP abuse (self-debugging control flow)

```c
/* the SIGTRAP handler is where the real work happens.
   Under a debugger, gdb eats the trap and the handler never runs. */
void handler(int sig) { real_work(); }
int main(void) { signal(SIGTRAP, handler); __asm__("int3"); }
```

Bypass in gdb: `handle SIGTRAP nostop noprint pass` so the signal is delivered to the
program instead of being consumed by the debugger. The same applies to SIGSEGV-driven
obfuscation: `handle SIGSEGV nostop noprint pass` and put your breakpoint on the handler.

### 6. Breakpoint-byte scanning and .text checksums

```c
/* a 0xCC anywhere in the function means a software breakpoint */
for (unsigned char *p = (unsigned char *)check; p < end; p++)
    if (*p == 0xCC) exit(1);
/* or: sum every byte of .text and compare against a baked-in constant */
```

Bypass: use **hardware** breakpoints (`hbreak` in gdb, max 4) which do not modify memory,
or patch the scanning loop, or set the breakpoint on the instruction *after* the checksum
compare.

### 7. Environment and miscellaneous probes

| Check | C | Bypass |
|---|---|---|
| `getenv("LD_PRELOAD")` | non-NULL means preload | unset it and use gdb instead |
| gdb sets `LINES`/`COLUMNS` | `getenv("LINES")` | `unset env LINES` / `unset env COLUMNS` in gdb |
| `personality(ADDR_NO_RANDOMIZE)` | detects a disabled-ASLR parent | gdb: `set disable-randomization off` |
| `prctl(PR_SET_DUMPABLE, 0)` | prevents attaching / core dumps | irrelevant if you start under gdb |
| `/proc/self/cmdline` has "gdb" | argv inspection | rename the binary / use `exec -a` |
| `fork()` + parent ptraces child | double-process trick | `set follow-fork-mode child`, `set detach-on-fork off` |
| `getauxval(AT_SECURE)` / `/proc/self/maps` shows `vgpreload` | valgrind detection | use perf or gdb |

The fork+ptrace trick is worth spelling out: the process forks, the **parent** attaches to
the **child** with `PTRACE_ATTACH`, so no debugger can attach to the child. In gdb:

```
(gdb) set detach-on-fork off
(gdb) set follow-fork-mode child
(gdb) info inferiors
(gdb) inferior 2
```

## Code - the universal LD_PRELOAD anti-anti-debug shim

```c
/* noptrace.c - neutralise ptrace, TracerPid and the usual environment probes.
 *   gcc -shared -fPIC -o noptrace.so noptrace.c -ldl
 *   LD_PRELOAD=./noptrace.so gdb -q ./chall
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

static const char *FAKE_STATUS = "/tmp/.fake_status";

/* 1. ptrace() always succeeds and does nothing. */
long ptrace(int request, ...) {
    (void)request;
    return 0;
}

/* 2. Redirect /proc/self/status (and /proc/<pid>/status) to a doctored copy. */
static void ensure_fake(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    FILE *out = fopen(FAKE_STATUS, "w");
    if (!out) return;
    fprintf(out, "Name:\tchall\nState:\tR (running)\nTracerPid:\t0\nUid:\t1000\n");
    fclose(out);
}

static int is_status(const char *path) {
    return path && strstr(path, "/status") && strstr(path, "/proc");
}

FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real)(const char *, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "fopen");
    if (is_status(path)) { ensure_fake(); path = FAKE_STATUS; }
    return real(path, mode);
}

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...);
    va_list ap; mode_t mode = 0;
    if (!real) real = dlsym(RTLD_NEXT, "open");
    va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    if (is_status(path)) { ensure_fake(); path = FAKE_STATUS; }
    return real(path, flags, mode);
}

/* 3. Hide LD_PRELOAD and the gdb-set terminal variables from getenv(). */
char *getenv(const char *name) {
    static char *(*real)(const char *);
    if (!real) real = dlsym(RTLD_NEXT, "getenv");
    if (!strcmp(name, "LD_PRELOAD") || !strcmp(name, "LD_AUDIT") ||
        !strcmp(name, "LINES") || !strcmp(name, "COLUMNS"))
        return NULL;
    return real(name);
}

/* 4. Parent is always init, never gdb. */
pid_t getppid(void) { return 1; }
```

```sh
# Build and use
gcc -shared -fPIC -o noptrace.so noptrace.c -ldl
LD_PRELOAD=$PWD/noptrace.so ./chall
# Under gdb, set it inside the session so gdb itself is not affected
gdb -q -ex 'set environment LD_PRELOAD ./noptrace.so' -ex run ./chall
```

## Code - a gdb Python plugin that auto-defeats ptrace and rdtsc

```python
#!/usr/bin/env python3
"""antianti.py - source this inside gdb:  (gdb) source antianti.py

  - forces every ptrace() call to return 0
  - zeroes rdx:rax after every rdtsc so timing deltas are always 0
  - passes SIGTRAP through to the inferior so int3-driven control flow still works

Only meaningful inside gdb; guarded so `python3 -m py_compile` and plain execution work.
"""
try:
    import gdb  # type: ignore
except ImportError:  # running outside gdb
    gdb = None


class PtraceBreak(gdb.Breakpoint if gdb else object):
    """Break on the ptrace PLT stub and immediately return 0."""

    def stop(self):
        gdb.execute("return 0", to_string=True)
        return False          # False => do not halt the user


class RdtscBreak(gdb.Breakpoint if gdb else object):
    """Break at a given rdtsc address and zero the timestamp."""

    def stop(self):
        gdb.execute("set $rax = 0", to_string=True)
        gdb.execute("set $rdx = 0", to_string=True)
        return False


def find_rdtsc() -> list[int]:
    """Scan the disassembly of the main objfile for rdtsc instructions."""
    out = gdb.execute("info functions", to_string=True)
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("0x"):
            try:
                body = gdb.execute(f"disassemble {parts[-1]}", to_string=True)
            except gdb.error:
                continue
            for dline in body.splitlines():
                if "rdtsc" in dline:
                    addrs.append(int(dline.split()[0], 16))
    return addrs


def install() -> None:
    gdb.execute("set confirm off")
    gdb.execute("set pagination off")
    gdb.execute("handle SIGTRAP nostop noprint pass")
    gdb.execute("unset env LINES")
    gdb.execute("unset env COLUMNS")
    try:
        PtraceBreak("ptrace")
        print("[antianti] ptrace hooked")
    except gdb.error:
        print("[antianti] no ptrace symbol (static binary?) - use: catch syscall ptrace")
    for addr in find_rdtsc():
        RdtscBreak(f"*{addr:#x}")
        print(f"[antianti] rdtsc hooked at {addr:#x}")


if gdb is not None:
    install()
else:
    print("antianti.py is a gdb script: run  gdb -x antianti.py ./chall")
```

For a statically linked binary there is no `ptrace` symbol; use the syscall catcher instead:

```
(gdb) catch syscall ptrace
(gdb) commands
>silent
>set $rax = 0
>continue
>end
(gdb) run
```

## Windows checks

| Check | How it works | Bypass |
|---|---|---|
| `IsDebuggerPresent()` | reads `PEB->BeingDebugged` (fs:[0x30]+2 / gs:[0x60]+2) | patch the byte to 0, or ScyllaHide |
| `CheckRemoteDebuggerPresent()` | wraps `NtQueryInformationProcess(ProcessDebugPort)` | patch the branch |
| Manual PEB read | `mov rax, gs:[0x60]; movzx eax, byte [rax+2]` | `set` the PEB byte in x64dbg |
| `PEB->NtGlobalFlag` == 0x70 | heap flags set by the debug heap | zero the field, or `_NO_DEBUG_HEAP=1` |
| Heap flags `ForceFlags`/`Flags` | debug heap leaves tell-tale values | ScyllaHide "Protect heap flags" |
| `NtQueryInformationProcess(ProcessDebugPort=7)` | non-zero => debugged | hook and return 0 |
| `NtQueryInformationProcess(ProcessDebugObjectHandle=0x1e)` | handle => debugged | hook |
| `NtSetInformationThread(ThreadHideFromDebugger=0x11)` | detaches the thread from the debugger | block the call |
| `OutputDebugStringA` + `GetLastError` | old trick: error is cleared only when debugged | patch |
| `GetThreadContext` -> Dr0-Dr3, Dr7 | detects hardware breakpoints | use software breakpoints or zero the context |
| `CloseHandle(0x1234)` invalid handle | raises `STATUS_INVALID_HANDLE` under a debugger | swallow the exception |
| `int 0x2d` / `int3` / `icebp (0xf1)` | exception behaviour differs under a debugger | pass the exception to the app |
| `FindWindowA("OLLYDBG")`, `Process32Next` scan | looks for debugger windows/processes | rename the debugger |
| `NtQuerySystemInformation(SystemKernelDebuggerInformation)` | kernel debugger check | hook |

The one-stop bypass on Windows is **ScyllaHide** (x64dbg/IDA/OllyDbg plugin) or **TitanHide**
(kernel driver): they hook exactly the above list. Enable the "x64dbg ultra" profile first,
then disable options until the target stops working to learn which check it used.

## Attack - a generic procedure

1. Run under `ltrace -S` and look for the last syscall before the bad exit. That names the
   check most of the time.
2. If nothing obvious, `catch syscall ptrace` / `break exit` and walk the backtrace
   (`bt`) to the caller.
3. Patch or hook. Prefer *hooking in the debugger* while you explore, and *patching the
   file* once you know exactly which branch to flip (see `binary-patching`).
4. If the binary is heavily protected, sidestep entirely: run it under qemu-user (no ptrace
   involved), emulate the relevant function with Unicorn, or solve it statically with angr.

## Variants & pitfalls

- **Multiple checks in `.init_array`** run before `main`; `break main` is already too late.
  Use `starti` and `objdump -s -j .init_array ./chall` to list the constructors.
- **Checks inside a thread**: `break pthread_create` and follow the start routine.
- **The check result is used, not just branched on** - e.g. `key ^= (traced ? 0 : 0x5a)`.
  Patching the branch then yields garbage output: you must make the check *return the right
  value*, not skip it.
- **Anti-anti-debug detection**: the binary may check that `ptrace` returns exactly what a
  real kernel would (e.g. call it twice - the second `PTRACE_TRACEME` should fail with
  EPERM). A shim that always returns 0 is itself a tell.
- **Static binaries** have no PLT to hook; `LD_PRELOAD` does nothing. Patch or use gdb
  syscall catchpoints.
- **seccomp** may block `ptrace` at the kernel level; check with
  `grep Seccomp /proc/<pid>/status`.
- Under **qemu-user** most Linux anti-debug simply works in your favour: `ptrace` is
  emulated, `rdtsc` is deterministic, and `/proc/self/status` reflects the qemu process.

## Tools

- `gdb` - `catch syscall`, `handle`, `return`, `hbreak`, Python API.
- `ScyllaHide` / `TitanHide` - Windows user-mode and kernel-mode anti-anti-debug.
- `frida` - `Interceptor.replace(Module.getExportByName(null, "ptrace"), ...)`.
- `qemu-user` - sidestep rather than bypass.
- `strace`/`ltrace` - locate the probe in seconds.

## References

- Linux `man 2 ptrace` (PTRACE_TRACEME semantics, one-tracer rule).
- `man 5 proc` - the `TracerPid` field of `/proc/[pid]/status`.
- ScyllaHide project documentation (option list maps 1:1 to the Windows table above).
