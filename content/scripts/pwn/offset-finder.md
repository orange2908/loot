---
title: "Offset Finder - Automated Crash-Offset Discovery with cyclic + Core Dumps"
category: pwn
subcategory: tooling
type: script
tags: [pwntools, cyclic, de-bruijn, offset, core-dump, buffer-overflow, stack-overflow, checksec, gdb, gef, pwndbg, canary, pie, nx, relro, aslr, gets, strcpy, scanf, read]
summary: "Script that drives a local binary with cyclic patterns, reads the core dump, reports the saved-rip offset, prints checksec and the suggested next technique."
tools: [pwntools, gdb, checksec, ulimit]
related: [exploit-template, pwntools-cheatsheet, gdb-gef-pwndbg-cheatsheet, stack-buffer-overflow-basics, stack-ret2win, mitigation-canary-bypass, rop-fundamentals]
---

## What it does

Given a local binary it:

1. Prints a triage report (arch, RELRO, canary, NX, PIE, static, interesting symbols).
2. Sends De Bruijn patterns of growing length until the process dies.
3. Reads the resulting core dump and derives the offset from **both** `rip`/`eip`
   and the top of the stack (`rsp`/`esp`), because when a canary or a
   `__stack_chk_fail` fires the pattern shows up in `rsp` rather than in `rip`.
4. Verifies the offset by sending `cyclic(offset) + b'BBBBBBBB'` and checking the
   crash address is exactly `0x4242...`.
5. Prints the technique shortlist implied by checksec.

## Prerequisites

```bash
# Core dumps must actually land next to the binary, not get eaten by apport
ulimit -c unlimited
cat /proc/sys/kernel/core_pattern
sudo sysctl -w kernel.core_pattern=core
sudo systemctl stop apport.service 2>/dev/null || true

# pwntools writes and reads the core for you
pip install -U pwntools
```

## Usage

```bash
python3 offset_finder.py ./vuln
python3 offset_finder.py ./vuln --max 2000 --step 200
python3 offset_finder.py ./vuln --prompt '> '        # send after a prompt
python3 offset_finder.py ./vuln --arg AAAA           # extra argv for the target
python3 offset_finder.py ./vuln --no-verify
python3 offset_finder.py ./vuln --stdin-file         # feed via a file instead of a pipe
```

## The script

```python
#!/usr/bin/env python3
"""offset_finder.py - find the saved-return-address offset of a local binary.

    python3 offset_finder.py ./vuln [--max N] [--step N] [--prompt 'str']

Strategy:
  * grow a De Bruijn pattern until the process crashes
  * pull rip/eip and rsp/esp out of the core dump
  * cyclic_find() both, prefer the rip match, fall back to the stack match
  * verify by replaying with a marker value

Works for plain stack smashes. If the binary has a canary the crash lands in
__stack_chk_fail and rip will not contain pattern bytes - the script detects
that and reports the *buffer-to-canary* distance instead.
"""

import argparse
import os
import re
import sys

from pwn import *

MARKER64 = b'BBBBBBBB'
MARKER32 = b'BBBB'


# ------------------------------------------------------------------ recon --
def triage(path):
    elf = ELF(path, checksec=False)
    context.binary = elf

    log.info('file      : %s', path)
    log.info('arch      : %s / %d-bit / %s', elf.arch, elf.bits, elf.endian)
    log.info('type      : %s', 'static' if elf.statically_linked else 'dynamic')
    log.info('RELRO     : %s', elf.relro)
    log.info('Canary    : %s', elf.canary)
    log.info('NX        : %s', elf.nx)
    log.info('PIE       : %s', elf.pie)
    log.info('Fortify   : %s', bool(elf.fortify) if hasattr(elf, 'fortify') else 'n/a')

    interesting = ('win', 'flag', 'backdoor', 'shell', 'get_flag', 'secret',
                   'system', 'execve', 'mprotect', 'gets', 'strcpy', 'sprintf',
                   'scanf', '__isoc99_scanf', 'read', 'printf', 'puts', 'memcpy')
    found = [(n, a) for n, a in elf.symbols.items() if n in interesting]
    for name, addr in sorted(found, key=lambda kv: kv[1]):
        log.info('symbol    : %-16s %#x', name, addr)

    try:
        binsh = next(elf.search(b'/bin/sh\x00'))
        log.info('string    : /bin/sh @ %#x', binsh)
    except StopIteration:
        pass

    return elf


def dangerous_calls(elf):
    """Cheap import-table check for the usual suspects."""
    bad = ('gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf',
           '__isoc99_scanf', 'alloca', 'memcpy', 'read')
    return sorted({n for n in elf.plt if n in bad} |
                  {n for n in elf.symbols if n in bad})


# -------------------------------------------------------------- crash loop --
def run_once(path, payload, argv, prompt, use_file):
    """Send payload, wait for exit, return a Corefile or None."""
    with context.local(log_level='error'):
        if use_file:
            write('/tmp/_offset_input', payload)
            io = process([path] + argv, stdin=open('/tmp/_offset_input', 'rb'))
        else:
            io = process([path] + argv)
            if prompt:
                try:
                    io.recvuntil(prompt.encode(), timeout=1)
                except EOFError:
                    pass
            io.sendline(payload)
        try:
            io.wait(timeout=10)
        except Exception:
            io.kill()
            return None
        core = io.corefile if io.poll() in (-11, -6, -4, -7, -8) else None
        io.close()
    return core


def pattern_offsets(core, n):
    """Return (rip_offset, sp_offset) - either may be None."""
    word = 8 if n == 8 else 4
    pc = core.pc
    sp = core.sp

    rip_off = None
    try:
        rip_off = cyclic_find(pack(pc, word * 8), n=n)
    except (ValueError, IndexError):
        rip_off = None
    if rip_off is not None and rip_off < 0:
        rip_off = None

    sp_off = None
    try:
        data = core.read(sp, word)
        sp_off = cyclic_find(data, n=n)
        if sp_off is not None and sp_off >= 0:
            # the stack slot at rsp is the one AFTER the saved return address
            sp_off = sp_off - word
        else:
            sp_off = None
    except (ValueError, IndexError, Exception):
        sp_off = None

    return rip_off, sp_off


def find_offset(path, argv, prompt, use_file, max_len, step):
    n = 8 if context.bits == 64 else 4
    p = log.progress('probing')
    for length in range(step, max_len + 1, step):
        p.status('pattern length %d', length)
        payload = cyclic(length, n=n)
        core = run_once(path, payload, argv, prompt, use_file)
        if core is None:
            continue

        signal_name = core.signal
        rip_off, sp_off = pattern_offsets(core, n)
        log.info('crash: signal=%s pc=%#x sp=%#x', signal_name, core.pc, core.sp)

        if rip_off is not None:
            p.success('saved return address at offset %d (from pc)', rip_off)
            return rip_off, 'pc', core
        if sp_off is not None and sp_off >= 0:
            p.success('saved return address at offset %d (from sp)', sp_off)
            return sp_off, 'sp', core

        # Canary case: pc points into __stack_chk_fail / abort, no pattern in pc.
        log.warning('crashed but no pattern in pc/sp - likely a stack canary '
                    '(SIGABRT from __stack_chk_fail). Length %d already smashes '
                    'the canary.', length)
        p.failure('canary detected')
        return None, 'canary', core

    p.failure('no crash up to %d bytes' % max_len)
    return None, None, None


def verify(path, argv, prompt, use_file, offset):
    n = 8 if context.bits == 64 else 4
    marker = MARKER64 if n == 8 else MARKER32
    expect = u64(marker) if n == 8 else u32(marker)
    payload = cyclic(offset, n=n) + marker
    core = run_once(path, payload, argv, prompt, use_file)
    if core is None:
        log.failure('verification run did not crash')
        return False
    got = core.pc & ((1 << (n * 8)) - 1)
    if got == expect:
        log.success('verified: pc == %#x with offset %d', got, offset)
        return True
    log.failure('verification mismatch: pc = %#x, expected %#x', got, expect)
    return False


# ------------------------------------------------------------ next steps ----
def suggest(elf, offset, mode):
    print()
    log.info('=== suggested next steps ===')
    lines = []

    if mode == 'canary':
        lines.append('A stack canary is in the way. Leak it first:')
        lines.append('  - format string: %N$p scan for a value ending in 00')
        lines.append('  - off-by-one on the canary null terminator, then puts()')
        lines.append('  - byte-by-byte brute force against a fork server')
        lines.append('  see mitigation-canary-bypass')

    if offset is not None:
        lines.append('offset = %d  ->  payload = cyclic(%d) + p%d(target)'
                     % (offset, offset, elf.bits))

    if 'win' in elf.symbols or 'flag' in elf.symbols or 'backdoor' in elf.symbols:
        lines.append('A win-style symbol exists -> ret2win (see stack-ret2win).')
        if elf.bits == 64:
            lines.append('  amd64: add a bare `ret` gadget first if it calls printf/system')

    if not elf.nx:
        lines.append('NX is OFF -> ret2shellcode into the buffer is on the table '
                     '(see shellcode-ret2shellcode).')
    else:
        lines.append('NX is ON -> ROP. Start with:')
        lines.append('  ROPgadget --binary %s --only "pop|ret"' % elf.path)
        lines.append('  see rop-fundamentals / rop-ret2libc')

    if elf.pie:
        lines.append('PIE is ON -> you need a code-pointer leak before any gadget '
                     'address is usable (see mitigation-partial-overwrite-brute).')
    else:
        lines.append('PIE is OFF -> ELF addresses are absolute, gadgets usable now.')

    if elf.relro == 'Partial RELRO':
        lines.append('Partial RELRO -> the GOT is writable (see rop-got-overwrite).')
    elif elf.relro == 'Full RELRO':
        lines.append('Full RELRO -> no GOT overwrite; pivot/ROP instead '
                     '(see mitigation-modern-playbook).')

    if elf.statically_linked:
        lines.append('Static binary -> no libc leak needed, build execve from '
                     'syscall gadgets (see rop-static-binary).')

    bad = dangerous_calls(elf)
    if bad:
        lines.append('dangerous calls present: %s' % ', '.join(bad))

    for line in lines:
        print('  ' + line)
    print()


# ----------------------------------------------------------------- main -----
def main():
    ap = argparse.ArgumentParser(description='find the saved-rip offset')
    ap.add_argument('binary')
    ap.add_argument('--max', type=int, default=1024, help='max pattern length')
    ap.add_argument('--step', type=int, default=128, help='length increment')
    ap.add_argument('--prompt', default=None, help='recvuntil this before sending')
    ap.add_argument('--arg', action='append', default=[], help='extra argv entry')
    ap.add_argument('--stdin-file', action='store_true',
                    help='feed the payload via a file instead of a pipe')
    ap.add_argument('--no-verify', action='store_true')
    opts = ap.parse_args()

    path = os.path.abspath(opts.binary)
    if not os.path.exists(path):
        log.error('no such file: %s', path)
        return 1
    os.chmod(path, 0o755)

    elf = triage(path)
    print()

    offset, mode, core = find_offset(path, opts.arg, opts.prompt,
                                     opts.stdin_file, opts.max, opts.step)

    if offset is not None and not opts.no_verify:
        verify(path, opts.arg, opts.prompt, opts.stdin_file, offset)

    if core is not None:
        log.info('core dump kept at: %s', getattr(core, 'path', '<in memory>'))

    suggest(elf, offset, mode)
    return 0 if offset is not None or mode == 'canary' else 2


if __name__ == '__main__':
    sys.exit(main())
```

## The 6-line version, for when you just want the number

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './vuln'
io = process('./vuln')
io.sendline(cyclic(500, n=8))
io.wait()
core = io.corefile
log.success('offset = %d', cyclic_find(core.read(core.rsp, 8), n=8))
```

## Doing it by hand in gdb

```gdb
# gef
gef> pattern create 300
gef> r
# ... SIGSEGV ...
gef> pattern search $rsp
gef> pattern search $rip

# pwndbg
pwndbg> cyclic -n 8 300
pwndbg> r
pwndbg> cyclic -n 8 -l $rsp
```

```bash
# Or entirely from the shell
python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(300, n=8))" > pat
gdb -q -batch -ex 'r < pat' -ex 'x/gx $rsp' -ex 'p $rip' ./vuln
python3 -c "from pwn import *; print(cyclic_find(0x6161616161616167, n=8))"
```

## Why both `rip` and `rsp`

```text
No canary, NX off/on, plain smash
  -> `ret` pops your pattern straight into rip. cyclic_find(rip) works.

You overwrote the saved rip with a NON-pattern value (e.g. you were testing a
target address) or the return target is unmapped
  -> rip is your value, but the stack at rsp still holds the NEXT pattern word.
     offset = cyclic_find(*rsp) - word_size

Canary present
  -> the smash is detected in the epilogue; the process aborts inside
     __stack_chk_fail. rip points into libc, and there is no pattern anywhere
     useful. The length at which it starts aborting tells you the
     buffer-to-canary distance: the canary sits at offset (that_length rounded
     down to a word). saved rip is at canary_offset + 2*word on the usual
     x86-64 layout (canary, saved rbp, saved rip).

Overflow via memcpy/strcpy with a fixed size
  -> the crash may happen inside the copy, not at the ret. Reduce the pattern
     length until the crash moves to the ret.
```

## Gotchas

```text
* cyclic() defaults to n=4. On amd64 an 8-byte rsp read will NOT be found in a
  4-subsequence pattern. Always pass n=8 for 64-bit.
* Cores are written to the CWD by default; `ulimit -c unlimited` is per-shell.
* If /proc/sys/kernel/core_pattern pipes to apport/systemd-coredump, pwntools
  cannot find the core. Set it to plain `core`.
* Setuid binaries never dump core. Copy the binary and drop the bit for testing.
* A binary that calls alarm() may die of SIGALRM before you finish; patch it out
  (`elf.asm(elf.plt['alarm'], 'ret'); elf.save('./vuln_noalarm')`) or use
  `handle SIGALRM nostop noprint pass` in gdb.
* Pattern bytes are lowercase ASCII. If the input is filtered to digits or
  uppercase, generate with a custom alphabet:
      cyclic(300, alphabet=string.digits.encode(), n=4)
* scanf("%s") stops at whitespace, gets() stops at \n, read() does not stop -
  the input function decides whether a long pattern even reaches the buffer.
```
