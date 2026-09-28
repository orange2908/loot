---
title: "Tool - pwntools"
category: pwn
subcategory: exploitation-framework
type: tool
tags: [pwntools, pwn, python, exploit-development, remote, process, elf, rop, shellcraft, cyclic, p64, u64, gdb-attach, packing, tubes]
summary: "The Python CTF exploit framework: process/remote tubes, ELF parsing, ROP building, shellcode generation, and gdb integration."
related: [pwn-triage, gdb-pwndbg-gef, ropgadget-ropper, one-gadget]
---

## What it is

`pwntools` is the standard Python library for writing exploits. It gives you a uniform interface (`tube`) over a local process, a remote socket, an SSH session and a gdb-attached process, plus helpers for everything else in a pwn workflow: packing, ELF/GOT/PLT lookup, ROP chain construction, shellcode assembly, and cyclic patterns.

## Install

```sh
# recommended: isolated, always current
pipx install pwntools
# or into a venv
python3 -m pip install --upgrade pwntools
# Debian/Ubuntu/Kali also package it
sudo apt install python3-pwntools
# verify
python3 -c "import pwn; print(pwn.__version__)"
pwn --help
```
The `pwn` CLI (`pwn cyclic`, `pwn checksec`, `pwn shellcraft`, `pwn disasm`) comes with it.

## The invocations that matter

```python
from pwn import *

# 1. set the architecture once; everything else follows from it
exe = context.binary = ELF("./chal", checksec=False)
context.log_level = "debug"          # "info" once it works
context.terminal = ["tmux", "splitw", "-h"]

# 2. the three tube types, interchangeable
io = process("./chal")
io = remote("chal.ctf", 1337)
io = remote("chal.ctf", 1337, ssl=True)
io = gdb.debug("./chal", gdbscript="b *main\nc")

# 3. the receive primitives you should actually use
io.recvuntil(b"> ")                  # anchor on a unique string
io.recvline()
io.recvn(16)
io.recvrepeat(1.0)                   # everything for 1 second
io.clean()                           # drain and discard

# 4. the send primitives
io.send(b"raw")
io.sendline(b"with newline")
io.sendafter(b"name: ", b"AAAA")     # wait for the prompt, then send
io.sendlineafter(b"> ", b"1")        # the one you will use most

# 5. packing and unpacking
payload = p64(0xdeadbeef) + p32(1) + p8(0x41)
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
leak = u64(io.recvn(6).ljust(8, b"\x00"))   # 6-byte libc addresses

# 6. ELF symbol lookup
exe.sym["main"]; exe.got["puts"]; exe.plt["puts"]; exe.address
libc = ELF("./libc.so.6", checksec=False)
libc.address = leak - libc.sym["puts"]       # set the base, all symbols shift
next(libc.search(b"/bin/sh\x00"))

# 7. ROP
rop = ROP(exe)
rop.call("puts", [exe.got["puts"]])
rop.raw(rop.find_gadget(["ret"])[0])
print(rop.dump())
payload = flat({72: rop.chain()})            # 72 bytes of padding, then the chain

# 8. cyclic offset finding
io.sendline(cyclic(200))
# after the crash, from gdb: cyclic_find(0x6161616161616166)

# 9. format string payloads
payload = fmtstr_payload(6, {exe.got["exit"]: exe.sym["win"]}, write_size="short")

# 10. shellcode
shellcode = asm(shellcraft.sh())
orw = asm(shellcraft.cat("/flag") if context.arch == "i386" else
          shellcraft.open("/flag") + shellcraft.read("rax", "rsp", 100) + shellcraft.write(1, "rsp", 100))

io.interactive()
```

Command-line helpers:
```sh
pwn checksec ./chal
pwn cyclic 200
pwn cyclic -l 0x6161616161616166
pwn shellcraft -f asm amd64.linux.sh
pwn disasm '4831c0' -c amd64
pwn asm 'xor rax, rax' -c amd64
pwn elfdiff a b
pwn template ./chal --host chal.ctf --port 1337 > solve.py    # generates a full skeleton
```

The `args` mechanism lets one script serve local and remote:
```python
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process("./chal")
# then run: ./solve.py            (local)
#           REMOTE=1 ./solve.py host port
#           GDB=1 ./solve.py      (attaches gdb)
```

## Gotchas

- **Everything is bytes.** `sendline("x")` raises in Python 3; use `b"x"`.
- `context.binary = ELF(...)` must be set **before** `asm`, `shellcraft`, `p64` sizing and `ROP` behave correctly for the target arch.
- `recv(n)` is not a guarantee of `n` bytes - use `recvn(n)`.
- `sendline` appends `context.newline` (`\n`). If the service wants `\r\n`, set `context.newline = b"\r\n"`.
- Local and remote stacks differ because of environment variables. Never hardcode a stack address found locally.
- `gdb.debug()` needs a terminal multiplexer configured in `context.terminal`, or it silently does nothing.
- `ELF()` prints a checksec banner every time; pass `checksec=False` in loops.
- `libc.address = X` must be set to the **base**, not to a symbol address. Compute `leak - libc.sym[name]`.
- `flat()` with a dict uses byte offsets as keys and pads with `context.cyclic` filler; verify with `hexdump`.
- Old challenge binaries may need `context.arch = "i386"` explicitly if `ELF` detection is confused.
- pwntools buffers aggressively in `debug` log level; if output looks reordered, that is the logger, not the target.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| pwntools not installable | raw `socket` + `struct.pack("<Q", x)` |
| You only need a tube | `nc`, `socat`, or `telnetlib`-style raw sockets |
| ROP chain building | `ROPgadget --binary ./chal --ropchain`, or `ropper` |
| Shellcode | `msfvenom -p linux/x64/exec CMD=/bin/sh -f python`, or hand-written asm via `nasm` |
| checksec | `checksec --file=`, or `readelf -lWa` / `rabin2 -I` |
| Binary patching | `patchelf`, `pwninit` |
| Windows targets | pwntools works but is Linux-centric; consider `winpwn` or raw sockets |
