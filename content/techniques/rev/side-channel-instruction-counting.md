---
title: "Side-Channel RE - Instruction Counting and Timing a Flag Checker"
category: rev
subcategory: side-channel
type: technique
tags: [side-channel, instruction-counting, perf, pin, pintool, callgrind, valgrind, qemu, unicorn, timing-attack, byte-by-byte, brute-force, flag-checker, early-exit, blackbox, tracing]
difficulty: medium
summary: "A checker that returns early on the first wrong byte leaks the flag: count instructions per candidate byte and keep the one that does the most work."
when_to_use:
  - "The binary is huge, obfuscated or VM-based and static analysis is too slow"
  - "The checker compares byte by byte and bails out early (memcmp-style, or a per-char loop)"
  - "angr explodes but the check is deterministic and cheap to run"
  - "You can run the target locally and control its stdin/argv"
tools: [perf, valgrind, callgrind, pin, qemu-user, unicorn, gdb, ltrace]
related: [unicorn-qiling-emulation, angr-symbolic-execution, dynamic-analysis-ltrace-ldpreload, crackme-patterns, obfuscation-deobfuscation]
---

## TL;DR

If `check()` stops at the first wrong character, the amount of work it does is a monotone
function of how many leading characters are correct. Count that work (instructions retired,
basic blocks executed, wall time) for all 95 printable candidates in position `i`; the
outlier is the right byte. Repeat for each position. Cost: `len(flag) * 95` executions.

## Recognise it

- The checker looks like this after decompilation:

```c
int check(const char *in) {
    for (int i = 0; i < 32; i++) {
        if (transform(in[i], i) != expected[i])
            return 0;               /* <-- early exit: the leak */
    }
    return 1;
}
```

- `strcmp`/`memcmp` on the flag (libc memcmp is not constant time either, but the
  per-iteration cost is tiny - count instructions, not cycles).
- The program prints "Wrong" instantly for garbage but takes measurably longer for a prefix
  of the real flag (heavy `transform`, sleeps, hash rounds per byte).
- A VM interpreter that dispatches per character - each extra correct byte is thousands of
  extra dispatch iterations, a huge signal.
- The binary is stripped/obfuscated but small enough to run 3000 times in a minute.

## Theory

Let `f(s)` be the number of instructions executed when the program is fed candidate `s`.
For an early-exit checker, `f` is (approximately) `base + k * prefix_len(s)`. Fix all but
position `i`, set positions `> i` to a constant filler, and sweep position `i` over the
alphabet. Exactly one candidate raises `f` by `k`. That candidate is `flag[i]`.

Preconditions that make it work:

1. **Determinism**. Same input -> same instruction count. ASLR, `getrandom`, timestamps and
   environment size perturb counts; instruction counting is far more stable than timing.
2. **Monotonicity**. Extra correct bytes must cost extra work. If the checker computes a
   hash over the whole string first and compares once, there is no signal - fall back to z3.
3. **Known length**. Sweep the *length* first: feed `"A"*n` for `n` in 1..64 and look for the
   n where the count jumps (the checker stops rejecting on length).

## Attack

1. Pick the measurement tool (see the comparison table below). Start with `perf stat`; if the
   noise is too high use Unicorn or `qemu-plugin`, both fully deterministic.
2. Calibrate: measure `f("A"*L)` five times. The spread must be much smaller than the step
   you expect. If `perf` jitters by thousands of instructions because of dynamic loading,
   switch to `valgrind --tool=callgrind` or count only the target function under gdb.
3. Determine the flag length.
4. For each position `i` from 0: sweep the alphabet, take `argmax` of the count, append.
5. Sanity check: after each byte, the winning count should be higher than the previous
   position's winning count by a roughly constant step. If the step vanishes you have gone
   past the end or the checker uses a non-prefix structure.

## Measurement tools compared

| Tool | Granularity | Noise | Speed | Notes |
|---|---|---|---|---|
| `perf stat -e instructions:u` | whole process, user-mode | low-ish | ~5 ms/run | needs `perf_event_paranoid <= 2`; Linux only |
| `valgrind --tool=callgrind` | per-function, exact | zero | ~200 ms/run | slowest but perfectly deterministic |
| `qemu-<arch> -plugin libinsn.so` | whole run, exact | zero | ~30 ms/run | works for foreign arch too |
| Intel PIN inscount | whole run or per-image | zero | ~50 ms/run | needs the PIN kit; best for Windows |
| Unicorn `UC_HOOK_CODE` | the emulated range only | zero | ~1 ms/run | fastest; needs the function to be self-contained |
| gdb `stepi` loop | tiny ranges only | zero | very slow | fine for <100k instructions |
| wall clock (`time.perf_counter`) | whole run | high | fastest | needs many repeats + median |

```sh
# --- perf: the default choice on Linux ------------------------------------
# instructions:u = user-space instructions only, excludes kernel noise
perf stat -e instructions:u -x, ./chall <<< "AAAAAAAA"
# -x, gives machine-readable CSV: "12345678,,instructions:u,..."
# If you get "Access to performance monitoring is restricted":
sudo sysctl -w kernel.perf_event_paranoid=1

# --- callgrind: exact, per-function ---------------------------------------
valgrind --tool=callgrind --callgrind-out-file=cg.out ./chall AAAA 2>/dev/null
# Ir = instructions read; the summary line gives the total
callgrind_annotate cg.out | head -30
# Count only one function (skip libc/loader startup noise entirely)
valgrind --tool=callgrind --toggle-collect=check --callgrind-out-file=cg.out ./chall AAAA

# --- qemu-user TCG plugin: deterministic, cross-arch ----------------------
# Ships with qemu source: contrib/plugins/libinsn.so (build with `make -C contrib/plugins`)
qemu-x86_64 -plugin /usr/lib/qemu/libinsn.so -d plugin ./chall AAAA 2>&1 | tail -3
# For an ARM or MIPS crackme, swap the qemu binary, everything else is identical
qemu-mipsel -L /usr/mipsel-linux-gnu -plugin /usr/lib/qemu/libinsn.so -d plugin ./chall AAAA

# --- ltrace / strace call counts (a coarse but free side channel) ---------
ltrace -c ./chall AAAA 2>&1 | tail -5
strace -c -f ./chall AAAA 2>&1 | tail -5
```

Intel PIN tool (the Windows/closed-source answer). Build against the PIN kit and run it:

```cpp
// inscount.cpp - build: make obj-intel64/inscount.so TARGET=intel64 PIN_ROOT=/opt/pin
#include "pin.H"
#include <cstdio>

static UINT64 icount = 0;

VOID docount() { icount++; }

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

VOID Fini(INT32 code, VOID *v) {
    fprintf(stderr, "ICOUNT %llu\n", (unsigned long long)icount);
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return 1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```

```sh
# Run the target under the pintool; ICOUNT goes to stderr
/opt/pin/pin -t /opt/pin/source/tools/MyTool/obj-intel64/inscount.so -- ./chall AAAA
```

## Code

A complete `perf`-driven byte-by-byte solver. Against the C target below it recovers the
flag in a few seconds.

```python
#!/usr/bin/env python3
"""icount_solve.py - recover a flag from an early-exit checker using perf instruction counts.

Usage:
    python3 icount_solve.py ./chall              # flag on stdin
    python3 icount_solve.py ./chall --argv       # flag as argv[1]

Requires Linux + perf, and kernel.perf_event_paranoid <= 2.
"""
import re
import string
import subprocess
import sys

ALPHABET = string.printable[:95]        # space .. '~'
FILLER = "."                            # padding for not-yet-known positions
MAXLEN = 48
PERF_RE = re.compile(rb"^(\d+),.*instructions", re.M)


def icount(binary: str, candidate: str, use_argv: bool, repeats: int = 1) -> int:
    """Median instruction count for one candidate string."""
    counts = []
    for _ in range(repeats):
        cmd = ["perf", "stat", "-x,", "-e", "instructions:u"]
        cmd += [binary, candidate] if use_argv else [binary]
        proc = subprocess.run(
            cmd,
            input=b"" if use_argv else candidate.encode() + b"\n",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        match = PERF_RE.search(proc.stderr)
        if not match:
            raise RuntimeError(
                "perf produced no instruction count; check perf_event_paranoid:\n"
                + proc.stderr.decode(errors="replace")[:400]
            )
        counts.append(int(match.group(1)))
    counts.sort()
    return counts[len(counts) // 2]


def find_length(binary: str, use_argv: bool) -> int:
    """The length whose count breaks away from the pack is usually the real one."""
    scores = {n: icount(binary, "A" * n, use_argv) for n in range(1, MAXLEN + 1)}
    best = max(scores, key=lambda n: scores[n])
    print(f"[*] length scan: best={best} ({scores[best]} instructions)")
    return best


def solve(binary: str, length: int, use_argv: bool) -> str:
    known = ""
    for pos in range(length):
        scores = {}
        for ch in ALPHABET:
            cand = known + ch + FILLER * (length - pos - 1)
            scores[ch] = icount(binary, cand, use_argv)
        best = max(scores, key=lambda c: scores[c])
        runner_up = sorted(scores.values())[-2]
        margin = scores[best] - runner_up
        known += best
        print(f"[{pos:02d}] {best!r} margin={margin:6d}  -> {known}")
        if margin < 8:
            print("[!] weak margin - the signal may be gone (wrong length? non-prefix check?)")
    return known


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    binary = sys.argv[1]
    use_argv = "--argv" in sys.argv[2:]
    length = find_length(binary, use_argv)
    flag = solve(binary, length, use_argv)
    print(f"\n[+] flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

The target it works against - compile with `gcc -O0 -o chall chall.c`:

```c
/* chall.c - a deliberately leaky early-exit checker */
#include <stdio.h>
#include <string.h>

static const unsigned char expected[] = {
    0x6d, 0x60, 0x66, 0x7b, 0x76, 0x2c, 0x25, 0x24,
    0x3c, 0x3f, 0x3b, 0x2f, 0x24, 0x68, 0x6c, 0x7e
};

static unsigned char transform(unsigned char c, int i) {
    /* busy work so each extra correct byte costs many instructions */
    unsigned char x = c ^ (unsigned char)(i * 7 + 0x13);
    for (int k = 0; k < 2000; k++)
        x = (unsigned char)((x << 1) | (x >> 7));
    return x;
}

int check(const char *in) {
    if (strlen(in) != sizeof(expected)) return 0;
    for (size_t i = 0; i < sizeof(expected); i++)
        if (transform((unsigned char)in[i], (int)i) != expected[i])
            return 0;               /* early exit leaks the prefix length */
    return 1;
}

int main(int argc, char **argv) {
    char buf[128] = {0};
    if (argc > 1) snprintf(buf, sizeof(buf), "%s", argv[1]);
    else if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;
    puts(check(buf) ? "Correct!" : "Wrong");
    return 0;
}
```

The same attack with Unicorn - zero noise, ~1000x faster, but you must emulate only the
checking function:

```python
#!/usr/bin/env python3
"""uc_icount.py - byte-by-byte flag recovery by counting emulated instructions.

Emulates one self-contained function of an x86-64 ELF and counts executed instructions
for each candidate byte. No syscalls may occur inside the emulated range.

Usage: python3 uc_icount.py ./chall 0x401196 16
       (binary, virtual address of check(), flag length)
"""
import string
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RIP, UC_X86_REG_RSP

CODE_BASE = 0x400000
CODE_SIZE = 0x200000
STACK_BASE = 0x7FFF0000
STACK_SIZE = 0x100000
INPUT_ADDR = 0x900000
RET_MAGIC = 0x1234000            # sentinel return address: stop when RIP lands here
ALPHABET = string.printable[:95]


def load_flat(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def run_once(image: bytes, func_addr: int, candidate: bytes) -> int:
    """Return the number of instructions executed by func(candidate)."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, CODE_SIZE)
    uc.mem_map(STACK_BASE - STACK_SIZE, STACK_SIZE * 2)
    uc.mem_map(INPUT_ADDR, 0x1000)
    uc.mem_map(RET_MAGIC & ~0xFFF, 0x1000)

    # Map the file image flat at CODE_BASE (fine for a non-PIE ELF whose vaddr base is 0x400000)
    uc.mem_write(CODE_BASE, image[: CODE_SIZE - 1])
    uc.mem_write(INPUT_ADDR, candidate + b"\x00")

    uc.reg_write(UC_X86_REG_RSP, STACK_BASE)
    uc.mem_write(STACK_BASE, RET_MAGIC.to_bytes(8, "little"))
    uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)

    counter = {"n": 0}

    def on_code(_uc, _address, _size, _user):
        counter["n"] += 1

    uc.hook_add(UC_HOOK_CODE, on_code)
    try:
        uc.emu_start(func_addr, RET_MAGIC, timeout=2_000_000, count=50_000_000)
    except Exception as exc:          # unmapped read, bad instruction, timeout
        print(f"[!] emulation stopped at {uc.reg_read(UC_X86_REG_RIP):#x}: {exc}",
              file=sys.stderr)
    return counter["n"]


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    image = load_flat(sys.argv[1])
    func_addr = int(sys.argv[2], 0)
    length = int(sys.argv[3], 0)

    known = b""
    for pos in range(length):
        scores = {}
        for ch in ALPHABET:
            cand = known + ch.encode() + b"." * (length - pos - 1)
            scores[ch] = run_once(image, func_addr, cand)
        best = max(scores, key=lambda c: scores[c])
        known += best.encode()
        print(f"[{pos:02d}] {best!r} -> {known.decode(errors='replace')}")
    print(f"\n[+] flag: {known.decode(errors='replace')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Timing instead of counting

When you cannot run the binary locally (remote service, anti-instrumentation), fall back to
wall-clock timing. The recipe changes only in the measurement function:

```python
#!/usr/bin/env python3
"""timing_probe.py - median-of-N timing oracle skeleton for a remote checker."""
import statistics
import subprocess
import time


def timed(binary: str, candidate: str, repeats: int = 15) -> float:
    """Median wall-clock seconds - median, not mean, to reject scheduler outliers."""
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        subprocess.run([binary, candidate],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


if __name__ == "__main__":
    print(f"{timed('/bin/true', 'x'):.6f}s baseline")
```

Rules for timing: always use the **median** of at least 15 runs, interleave candidates
(measure a, b, c, a, b, c - not aaaa, bbbb) so thermal drift affects everyone equally, pin
to a core with `taskset -c 3`, and expect to need 10x more samples than you think.

## Variants & pitfalls

- **No early exit**: the checker accumulates `diff |= in[i] ^ exp[i]` and compares once.
  There is no prefix signal - use z3 or angr instead.
- **Hash-then-compare**: `sha256(input) == const`. No signal at all. Look elsewhere.
- **Length check first**: every wrong-length candidate returns immediately, so the length
  sweep is trivially visible. Do it first and the per-byte sweep gets much cleaner.
- **Non-prefix order**: some checkers verify indices in a shuffled order (`for i in perm`).
  The attack still works, but the byte you recover at "step 0" is not `flag[0]` - run the
  sweep for *every* position independently with a fixed filler and see which position's
  count changes.
- **Interdependent bytes** (e.g. `flag[i] ^ flag[i+1]` checked together): per-byte sweeps
  fail. Sweep pairs (95^2 = 9025 runs per pair, still cheap).
- **ASLR / environment noise in perf**: run with `setarch $(uname -m) -R` to disable ASLR
  and keep the environment identical between runs (`env -i`), since argv/envp size changes
  the initial stack setup work.
- **Counting the loader too**: ~200k instructions of `ld.so` noise swamp a 2k signal. Use
  `--toggle-collect` in callgrind, or a PIN tool filtered to the main image, or Unicorn.
- **Anti-instrumentation**: some binaries detect valgrind (`/proc/self/maps` shows
  `vgpreload`) or PIN (parent process name). perf is undetectable from userspace.
- **Margin sanity**: the winning candidate should beat the runner-up by roughly the cost of
  one loop iteration. If the margin is 1-5 instructions you are reading noise.

## Tools

- `perf` (linux-tools) - `perf stat -e instructions:u -x,`.
- `valgrind` + `callgrind_annotate` - exact per-function Ir counts.
- `qemu-user` TCG plugins - `contrib/plugins/libinsn.so`, any guest architecture.
- Intel PIN - `inscount0.so` ships as a sample tool; works on Windows and Linux.
- `unicorn` - deterministic counting of an isolated function.
- `frida-trace` / `drrun` (DynamoRIO `drcov`) - basic-block coverage as an alternative signal.

## References

- Valgrind manual, Callgrind chapter (`--toggle-collect`, `callgrind_annotate`).
- QEMU documentation, "TCG Plugins" (`-plugin`, `-d plugin`).
- Intel PIN user guide, sample tool `inscount0`.
