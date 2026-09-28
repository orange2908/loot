---
title: "Dynamic Analysis - ltrace, strace, LD_PRELOAD and gdb Scripting"
category: rev
subcategory: dynamic-analysis
type: technique
tags: [ltrace, strace, ld-preload, dlsym, rtld-next, strcmp, memcmp, gdb, gdb-python, ptrace, patchelf, qemu-user, frida, ld-debug, catch-syscall, hooking, instruction-counting, shim]
difficulty: medium
summary: "Run the binary and let it tell you the flag: syscall/library tracing, an LD_PRELOAD strcmp shim, gdb scripting and a ptrace single-stepper."
when_to_use:
  - "The binary compares your input against something computed at runtime"
  - "Static analysis shows a decrypt-then-compare and you just want the plaintext"
  - "You need to know which files/sockets/syscalls it touches before reading code"
  - "The binary needs a libc or an architecture you do not have"
tools: [ltrace, strace, gdb, ld-preload, patchelf, qemu-user, frida, gcc, ldd]
related: [triage-unknown-binary, ghidra-workflow, ida-r2-binja-workflow, anti-debug-bypass, binary-patching, side-channel-instruction-counting, gdb-reversing-cheatsheet, crackme-patterns]
---

## TL;DR

Run the binary under a microscope before reading its code: `strace` shows
syscalls, `ltrace` shows libc calls, and an `LD_PRELOAD` shim hooking
`strcmp`/`memcmp` prints the expected value the moment it is compared. Static or
anti-`ltrace` targets fall back to scripted gdb or a `ptrace` single-stepper.

## Recognise it

- `ltrace` shows `strcmp("AAAA", "s3cr3t")` - done.
- Ghidra shows `decrypt(buf, key); if (memcmp(buf, input, 32) == 0)`: hook
  `memcmp`, read argument 1.
- `strace` shows `openat("/flag.txt")` or `connect()`: the flag is env, not computed.
- `ltrace` silent on a libc-using binary: statically linked, or it detects you.
- The program dies instantly under a debugger -> `anti-debug-bypass`.

## Theory - why LD_PRELOAD works

`ld.so` resolves a dynamic symbol in this order: the executable, then each object
in `LD_PRELOAD` in order, then the `DT_NEEDED` libraries breadth-first. A preloaded
object exporting `strcmp` therefore wins over libc's; you log the real arguments and
tail-call the real one via `dlsym(RTLD_NEXT, "strcmp")` - "the next definition after
me", i.e. libc's. Preconditions: dynamically linked, not setuid (the loader drops
`LD_PRELOAD` there), and the call must reach the PLT - GCC inlines short
constant-length `strcmp`/`memcmp` at `-O2`, so check
`objdump -d --disassemble=main ./chall | grep plt` before blaming your shim.

## Workflow

```sh
# --- strace: syscalls ---
strace -f ./chall                        # -f follows forks: the work is often in a child
strace -f -e trace=openat,read,write,connect,execve,ptrace,mmap,mprotect ./chall
strace -f -e trace=%file ./chall         # by category: also %network, %process, %signal
strace -s 4096 -f ./chall                # full string args (default truncates at 32)
strace -ttt -T ./chall                   # timestamps + time per call (timing channels)
strace -f -p "$(pgrep -f chall)"         # attach to a running process
strace -ff -o /tmp/trace ./chall         # one log per process, forks do not interleave
strace -e read=0 -e write=1 ./chall      # hexdump everything crossing fd 0 and fd 1
strace -c -f ./chall                     # count syscalls: a quick behaviour profile
# --- ltrace: library calls ---
ltrace -S -f ./chall                     # library calls + syscalls, following children
ltrace -e 'str*+mem*' ./chall            # -e is a glob filter: keep these
ltrace -e '*-malloc-free-printf' ./chall # ...or exclude the noisy ones
ltrace -x 'check_flag' ./chall           # -x traces a non-imported symbol by name
ltrace -x '@libcrypto.so.*' ./chall      # @ scopes the filter to one library
ltrace -s 200 ./chall                    # longer string args; -c counts calls
ltrace -c ./chall
echo 'AAAABBBBCCCCDDDD' | ltrace -e 'str*+mem*' ./chall   # non-interactive input
ltrace -F ./ltrace.conf -x 'check_flag+decrypt_buf' ./chall   # custom prototypes
# --- LD_DEBUG: watch ld.so resolve. "binding file ./chall to .../libc.so.6:
#     normal symbol 'strcmp'" with your preload loaded means it did not export
#     the symbol: wrong name, C++ mangling, static, non-default visibility. ---
LD_DEBUG=bindings ./chall 2>&1 | grep -i strcmp   # confirms your preload wins
LD_DEBUG=libs ./chall                             # search paths actually used
LD_DEBUG=all ./chall 2>/tmp/ld.log                # everything (very verbose)
LD_DEBUG=help ./chall                             # list the valid values
LD_DEBUG=bindings LD_DEBUG_OUTPUT=/tmp/ldbind ./chall   # log off stderr
# --- build and preload the shim ---
# -shared -fPIC: preloadable .so; -ldl: dlsym (glibc <2.34); -D_GNU_SOURCE: RTLD_NEXT
gcc -shared -fPIC -D_GNU_SOURCE -o hook.so hook.c -ldl
gcc -m32 -shared -fPIC -D_GNU_SOURCE -o hook32.so hook.c -ldl   # 32-bit target
LD_PRELOAD="$PWD/hook.so" ./chall     # absolute: relative is ignored in some setups
HOOKLOG=/tmp/hook.log LD_PRELOAD="$PWD/hook.so" ./chall   # keep stdout clean
echo AAAAAAAAAAAAAAAA | LD_PRELOAD="$PWD/hook.so" ./chall  # several: space/colon list
# [hook] loaded, pid=41233
# [memcmp] "AAAAAAAAAAAAAAAA\x00..." vs "flag{pr3l04d_1s_ch34t1ng}"  -> -1
```

`ltrace` guesses `long` for unknown prototypes; teach it in `~/.ltrace.conf`,
`./ltrace.conf` or a `-F` file:

```
; Syntax: <return> <name>(<arg>, <arg>);  Types: void int uint long ulong
; char* string addr file format void*; string[N] caps the dump; array(type,len)
int check_flag(string, int);
void decrypt_buf(string, ulong, uint);
int verify(string[64], string[64]);
hex(int) checksum(string);               ; hex-format a return value
```

## Code

### The LD_PRELOAD shim

```c
/* hook.c - LD_PRELOAD shim dumping every string/memory comparison: a crackme
 * doing `if (strcmp(input, decrypted) == 0) win();` leaks its flag on the
 * first run. The tail fakes ptrace/sleep/rand for anti-debug targets.
 * Build: gcc -shared -fPIC -D_GNU_SOURCE -o hook.so hook.c -ldl
 * Use:   LD_PRELOAD="$PWD/hook.so" ./chall      (log: stderr or $HOOKLOG)
 * Do NOT #include <sys/ptrace.h>: glibc's enum first arg clashes with ours. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* RTLD_NEXT; must precede every include */
#endif
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int    (*real_strcmp)(const char *, const char *);
static int    (*real_strncmp)(const char *, const char *, size_t);
static int    (*real_strcasecmp)(const char *, const char *);
static int    (*real_memcmp)(const void *, const void *, size_t);
static char  *(*real_strstr)(const char *, const char *);
static size_t (*real_strlen)(const char *);
static char  *(*real_getenv)(const char *);
static FILE *logfp;
#define LOGF (logfp ? logfp : stderr)
/* Resolve lazily from the NEXT object in the search order, i.e. libc. */
#define REAL(f) do { if (!real_##f) { real_##f = dlsym(RTLD_NEXT, #f); \
  if (!real_##f) { write(2, "[hook] dlsym failed\n", 20); _exit(1); } } } while (0)
#define SLEN(s) ((s) ? real_strlen(s) : (size_t)0)
__attribute__((constructor))        /* runs before main(), before any hook */
static void hook_init(void) {
    const char *p = getenv("HOOKLOG");
    logfp = (p && *p) ? fopen(p, "a") : NULL;
    if (!logfp) logfp = stderr;
    setvbuf(logfp, NULL, _IOLBF, 0);   /* line buffered: survives a crash */
    fprintf(logfp, "[hook] loaded, pid=%d\n", (int)getpid()); }
static void dump(const void *p, size_t n) {  /* escape non-printables, cap 128 */
    const unsigned char *b = (const unsigned char *)p; size_t i;
    if (!b) { fprintf(LOGF, "(null)"); return; }  fputc('"', LOGF);
    for (i = 0; i < n && i < 128; i++)
        if (b[i] >= 0x20 && b[i] < 0x7f && b[i] != '"' && b[i] != '\\')
            fputc((int)b[i], LOGF);
        else fprintf(LOGF, "\\x%02x", b[i]);
    fprintf(LOGF, "\"%s", n > 128 ? "..." : ""); }
static void log_cmp(const char *tag, const void *a, size_t na,
                    const void *b, size_t nb, int rv) {
    fprintf(LOGF, "[%s] ", tag); dump(a, na);
    fprintf(LOGF, " vs ");       dump(b, nb);
    fprintf(LOGF, "  -> %d%s\n", rv, rv == 0 ? "   *** MATCH ***" : ""); }
#define STRHOOK(f) int f(const char *a, const char *b) { \
    REAL(f); REAL(strlen); int rv = real_##f(a, b); \
    log_cmp(#f, a, SLEN(a), b, SLEN(b), rv); return rv; }
STRHOOK(strcmp)
STRHOOK(strcasecmp)
int strncmp(const char *a, const char *b, size_t n) {
    REAL(strncmp); int rv = real_strncmp(a, b, n);
    log_cmp("strncmp", a, n, b, n, rv); return rv; }
int memcmp(const void *a, const void *b, size_t n) {
    REAL(memcmp); int rv = real_memcmp(a, b, n);
    if (n >= 4) log_cmp("memcmp", a, n, b, n, rv);  /* skip libc's tiny ones */
    return rv; }
char *strstr(const char *hay, const char *ndl) {
    REAL(strstr); REAL(strlen); char *rv = real_strstr(hay, ndl);
    fprintf(LOGF, "[strstr] "); dump(ndl, SLEN(ndl));
    fprintf(LOGF, " -> %s\n", rv ? "found" : "not found"); return rv; }
size_t strlen(const char *s) {   /* not logged: far too noisy, but hookable */
    REAL(strlen); return real_strlen(s); }
char *getenv(const char *name) { /* anti-debug code reads LD_PRELOAD itself */
    REAL(getenv); REAL(strcmp);
    if (name && real_strcmp(name, "LD_PRELOAD") == 0) {
        fprintf(LOGF, "[getenv] hid LD_PRELOAD\n"); return NULL; }
    return real_getenv(name); }
long ptrace(long request, ...) { /* PTRACE_TRACEME is 0, and 0 means success */
    fprintf(LOGF, "[ptrace] request=%ld -> faked 0\n", request); return 0; }
unsigned int sleep(unsigned int sec) {
    fprintf(LOGF, "[sleep] %u seconds skipped\n", sec); return 0; }
int rand(void) { return 4; }     /* deterministic: every run reproducible */
/* Same pattern for time, srand, fopen (redirect /flag), getpid, puts/printf. */
```

### gdb scripting

```gdb
# check.gdb - a command file: gdb -q -x check.gdb --args ./chall AAAABBBB
set pagination off
set confirm off
set disassembly-flavor intel
handle SIGTRAP nostop noprint pass   # anti-debug raises SIGTRAP on purpose
break *check_flag
break memcmp                         # the libc compare, whoever calls it
commands 1-2
  silent
  printf "rdi=%s rsi=%s rdx=%ld\n", (char *)$rdi, (char *)$rsi, $rdx
  x/4gx $rsp
  info registers rax rbx rcx rdx rsi rdi
  continue
end
run
# --- more primitives, interactive or in the same file ---
catch syscall ptrace          # stops on entry AND return; name or number works
catch syscall 101             # ptrace on x86-64; also openat, exec, fork
catch signal SIGSEGV
catch load libcrypto.so.3     # stop when a library is loaded
starti                        # stop at the very first instruction
info proc mappings            # find the PIE load base
break *0x555555555000+0x11a7
break *($_base("chall") + 0x11a7)   # or let gdb do the maths
watch *(int *)0x404060        # hardware watchpoint on a write
rwatch *(char *)$rsi          # ...on a read
set follow-fork-mode child    # follow into children
set detach-on-fork off
record full                   # software record: slow but reversible
reverse-continue              # also reverse-stepi, reverse-next
dump binary memory /tmp/decrypted.bin $rsi $rsi+64
```

```python
"""gdb Python (more capable than a command file, and what you want for
per-character data): log every comparison and count instructions per run.
Load: gdb -q -x gdbhook.py --args ./chall AAAA  (or `source gdbhook.py`)
      (gdb) hooklog on ; run     -> every strcmp/strncmp/memcmp logged
      (gdb) starti ; countinsn   -> instruction-count side channel
"""
import gdb

def read_mem(addr, count, cstr=False):
    """Inferior memory; cstr=True cuts at the first NUL and decodes."""
    if int(addr) == 0 or count <= 0:
        return "(null)" if cstr else b""
    try:
        raw = bytes(gdb.selected_inferior().read_memory(int(addr),
                                                        min(count, 256)))
    except gdb.MemoryError:
        raw = b""
    return raw.split(b"\x00", 1)[0].decode("latin-1") if cstr else raw

def reg(name):                    # one register, as a Python int
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF

class CompareBreakpoint(gdb.Breakpoint):
    """Logs one comparison call's arguments, then keeps running."""
    def __init__(self, symbol, is_mem):
        super().__init__(symbol, gdb.BP_BREAKPOINT, internal=False)
        self.silent, self.symbol, self.is_mem = True, symbol, is_mem
    def stop(self):
        a, b, n = reg("rdi"), reg("rsi"), reg("rdx")
        if self.is_mem:
            a, b = read_mem(a, n), read_mem(b, n)
        else:
            a, b, n = read_mem(a, 128, True), read_mem(b, 128, True), -1
        print("[%s n=%d] %r vs %r" % (self.symbol, n, a, b))
        return False              # False = do not stop, keep running

class CountInstructions(gdb.Command):
    """(gdb) countinsn [cap] - single-step to exit and print the count; the
    right input byte makes the checker run longer, which is the channel."""
    def __init__(self):
        super().__init__("countinsn", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        cap, count = int(arg) if arg.strip() else 5_000_000, 0
        try:
            while count < cap:
                gdb.execute("stepi", to_string=True)
                count += 1
        except gdb.error as exc:  # "not being run" = it exited; that is it
            print("[countinsn] stopped: %s" % exc)
        print("[countinsn] executed %d instructions" % count)

class HookLog(gdb.Command):
    """(gdb) hooklog on|off - install or remove the comparison breakpoints."""
    def __init__(self):
        super().__init__("hooklog", gdb.COMMAND_USER)
        self.bps = []
    def invoke(self, arg, from_tty):
        for bp in self.bps:       # "off", or a re-install, clears them first
            bp.delete()
        self.bps = []
        if arg.strip() == "off":
            return
        for sym, is_mem in (("strcmp", 0), ("strncmp", 0), ("strcasecmp", 0),
                            ("memcmp", 1)):
            try:
                self.bps.append(CompareBreakpoint(sym, is_mem))
            except RuntimeError:  # absent: static binary, or not imported
                print("[hooklog] no symbol %s - skipped" % sym)

for _cmd in ("set pagination off", "set confirm off",
             "set disassembly-flavor intel",
             "handle SIGTRAP nostop noprint pass"):   # deliberate SIGTRAPs
    gdb.execute(_cmd)
CountInstructions()
HookLog()
print("[gdbhook] ready: `hooklog on` + `run`, or `starti` + `countinsn`")
```

### A minimal ptrace tracer

```c
/* tracer.c - when ltrace and LD_PRELOAD both fail (static binary, custom
 * loader), count instructions yourself: the right byte makes the checker loop
 * one more time. Single-step a child and count executed instructions.
 * Build: gcc -O2 -o tracer tracer.c
 * Use:   ./tracer ./chall AAAA  -> the input with the highest count is best.
 * Linux/x86-64; PTRACE_SINGLESTEP does ~100k steps/sec, fine for a crackme. */
#include <errno.h>
#include <stdio.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#define MAX_STEPS 50000000UL       /* stop runaway targets */
static int run_child(char **argv) {
    /* Ask the kernel to stop us at the first instruction after execve. */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) { perror("TRACEME"); _exit(127); }
    personality(ADDR_NO_RANDOMIZE);         /* stable addresses across runs */
    execv(argv[0], argv);
    perror("execv"); _exit(127); return 0; }
int main(int argc, char **argv) {
    pid_t child; int status; unsigned long steps = 0;
    struct user_regs_struct regs;
    if (argc < 2) { fprintf(stderr, "usage: %s <prog> [args]\n", argv[0]); return 1; }
    if ((child = fork()) == -1) { perror("fork"); return 1; }
    if (child == 0) return run_child(&argv[1]);
    /* First stop: the child has execve'd and sits at its entry point. */
    if (waitpid(child, &status, 0) == -1) { perror("waitpid"); return 1; }
    while (steps < MAX_STEPS) {
        if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) == -1) {
            if (errno != ESRCH) perror("SINGLESTEP");
            break; }                        /* ESRCH: the child is gone */
        if (waitpid(child, &status, 0) == -1) break;
        if (WIFEXITED(status)) { printf("[exit %d]\n", WEXITSTATUS(status)); break; }
        if (WIFSIGNALED(status)) { printf("[signal %d]\n", WTERMSIG(status)); break; }
        steps++;
        /* Progress, and a hint at where the program spends its time. */
        if (steps % 100000UL == 0 && ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0)
            printf("[tracer] %10lu steps, rip=0x%llx\n", steps,
                   (unsigned long long)regs.rip);
    }
    printf("INSTRUCTIONS %lu\n", steps);
    return 0; }
```

```sh
gcc -O2 -o tracer tracer.c   # count instructions per candidate byte, max wins
for c in $(python3 -c "print(' '.join(chr(x) for x in range(0x20,0x7f)))"); do
  echo "$(./tracer ./chall "flag{$c" | awk '/^INSTRUCT/{print $2}') $c"
done | sort -rn | head -5   # full driver: side-channel-instruction-counting
```

## Foreign libc and foreign architecture

```sh
# Run it against the libc.so.6 + ld-linux it shipped with, not yours, and
# copy first (cp chall chall.patched): patchelf edits in place.
ldd ./chall                                        # what does it need...
readelf -d ./chall | grep -E 'NEEDED|RPATH|RUNPATH|INTERP'
for f in interpreter needed rpath; do patchelf --print-$f ./chall; done
patchelf --set-interpreter "$PWD/ld-2.31.so" ./chall  # ld.so must match the libc
patchelf --set-rpath "$PWD" ./chall                # where that loader searches
patchelf --replace-needed libc.so.6 "$PWD/libc-2.31.so" ./chall
patchelf --add-needed "$PWD/hook.so" ./chall    # static LD_PRELOAD, survives setuid
./ld-2.31.so --library-path "$PWD" ./chall         # non-destructive alternative
LD_LIBRARY_PATH="$PWD" ./chall                     # ...or override for one run
# qemu-user: -L is the guest root (ld.so + libs), /usr/<arch>-linux-gnu or a rootfs
qemu-arm-static -L /usr/arm-linux-gnueabihf ./chall
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./chall   # also mips, mipsel, riscv64
qemu-mipsel-static -L ./squashfs-root ./usr/sbin/httpd  # extracted firmware rootfs
qemu-arm-static -strace -L /usr/arm-linux-gnueabihf ./chall   # guest syscall trace
qemu-arm-static -g 1234 -L /usr/arm-linux-gnueabihf ./chall & # gdbserver on :1234
gdb-multiarch -q ./chall -ex 'set architecture arm' -ex 'target remote :1234'
sudo update-binfmts --display | grep qemu   # binfmt_misc: ./chall "just works"
# LD_PRELOAD works under qemu if the shim is built for the GUEST arch:
# arm-linux-gnueabihf-gcc -shared -fPIC -o hook_arm.so hook.c -ldl
```

## frida - hook without rebuilding

```sh
# Beats a shim on Android/iOS/Windows or an already-running process: it writes
# an editable, live-reloaded JS stub per function into ./__handlers__
frida-trace -i 'strcmp' -i 'memcmp' -f ./chall   # -i: glob over exported names
frida-trace -i 'str*' -p "$(pgrep chall)"        # attach to a running pid
frida-trace -a 'chall!0x11a7' -f ./chall         # -a: unexported module!offset
frida-trace -U -i 'open*' -f com.example.app     # -U: USB device (Android)
```

```text
// __handlers__/libc.so/memcmp.js - edit the generated stub in place:
onEnter(log, args, state) { log('memcmp(' + Memory.readUtf8String(args[0]) +
  ', ' + Memory.readUtf8String(args[1]) + ', ' + args[2].toInt32() + ')'); }
```

## Variants & pitfalls

- **Inlined compares**: `-O2` compiles `strcmp(s, "abc")` to byte compares, no
  PLT, no hook. Check `objdump -d ./chall | grep -c 'strcmp@plt'`.
- **Static binaries have no PLT**: gdb breakpoints on static addresses, or the tracer.
- **setuid/setgid ignores `LD_PRELOAD`/`LD_LIBRARY_PATH`**: `patchelf --add-needed`, or gdb.
- **Detection**: `getenv("LD_PRELOAD")` (hook it), `/proc/self/environ` or `maps`,
  `PTRACE_TRACEME` failing. See `anti-debug-bypass`.
- **No recursion**: a `strcmp` hook calling `printf` (whose libc calls `strcmp`)
  loops forever; resolve the real symbol before logging.
- **`dlsym` can call `calloc`**, so a naive `malloc` shim deadlocks: use a `constructor`.
- **C++ mangling**: `std::string::compare` needs the `nm -D` mangled name, with the
  shim declared `extern "C"` plus `asm("mangled_name")`.
- **`ltrace` is fragile on modern glibc** (IFUNC `strcmp`, full RELRO, `-z
  now`): its silence on a dynamic binary proves nothing.
- **`strace -f` and fork bombs**: redirect to a file (`-o`) first.
- **Sandbox**: `docker run --rm -it -v "$PWD:/w" -w /w --network none ubuntu:22.04 ./chall`.
- **PIE plus ASLR invalidates your notes**: `setarch -R ./chall` or
  `personality(ADDR_NO_RANDOMIZE)` pins the base; gdb disables ASLR itself.

## Tools

- `strace`, `ltrace` (+ `ltrace.conf` / `-F` prototypes) - call tracing.
- `gdb` with Python, `pwndbg`/`gef`/`peda`, `gdb-multiarch`, `gdbserver`.
- `patchelf` - interpreter/RPATH/NEEDED rewriting; `qemu-user-static` - foreign arch.
- `ldd`, `readelf -d`, `LD_DEBUG` - linkage inspection.
- `frida`, `frida-trace`, `frida-gum` - dynamic instrumentation.
- `perf stat -e instructions:u`, `valgrind --tool=callgrind` - counts, no tracer.

## References

- `strace(1)`, `ltrace(1)`, `ltrace.conf(5)`, `ld.so(8)`, `dlsym(3)`, `ptrace(2)`,
  `patchelf(1)` manual pages.
- glibc manual, "Dynamic Linker" - `LD_PRELOAD` order and `RTLD_NEXT`.
- GDB manual, "Extending GDB / Python API" - `gdb.Breakpoint`, `gdb.Command`.
- QEMU docs, "User-mode emulation" (`-L`, `-strace`, `-g`); Frida docs (frida.re).
