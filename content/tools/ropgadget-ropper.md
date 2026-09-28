---
title: "Tool - ROPgadget / ropper"
category: pwn
subcategory: exploitation
type: tool
tags: [ropgadget, ropper, rop, gadget, pop-rdi, syscall, ropchain, stack-pivot, jop, srop, static-binary, pwn, exploitation, gadget-search]
summary: "Find ROP gadgets in a binary or libc, and auto-generate an execve chain for static binaries."
related: [pwn-triage, pwntools, one-gadget, gdb-pwndbg-gef]
---

## What it is

Both tools disassemble backwards from every `ret`/`jmp`/`call` and list the short instruction sequences ("gadgets") you can chain. `ROPgadget` additionally has `--ropchain`, which builds a complete `execve("/bin/sh", 0, 0)` chain automatically - which solves a static-binary challenge outright. `ropper` has a nicer query language and supports more architectures and file formats.

## Install

```sh
pipx install ROPgadget
pipx install ropper
# Debian/Kali
sudo apt install python3-ropgadget ropper
# verify
ROPgadget --version
ropper --version
```

## The invocations that matter

```sh
B=./chal

# 1. every gadget (start here, then grep)
ROPgadget --binary "$B"
ROPgadget --binary "$B" | wc -l

# 2. the gadgets you actually want, for the SysV calling convention
ROPgadget --binary "$B" --only 'pop|ret'
ROPgadget --binary "$B" | grep -E ': pop rdi ; ret$'
ROPgadget --binary "$B" | grep -E ': pop (rsi|rdx|rcx|rax|rbx|rbp|rsp) ; ret$'
ROPgadget --binary "$B" | grep -E ': (syscall|int 0x80) ; ret'
ROPgadget --binary "$B" | grep -E 'leave ; ret'           # stack pivot
ROPgadget --binary "$B" | grep -E ': ret$' | head -1      # the alignment ret

# 3. auto-generate a full execve chain (static, non-PIE binaries)
ROPgadget --binary "$B" --ropchain

# 4. find strings inside the binary (for /bin/sh)
ROPgadget --binary "$B" --string '/bin/sh'
ROPgadget --binary "$B" --memstr '/bin/sh'                # build the string byte by byte

# 5. restrict to a range or a section
ROPgadget --binary "$B" --range 0x400000-0x401000
ROPgadget --binary "$B" --depth 8                         # longer gadgets

# 6. ropper equivalents, with a search language
ropper --file "$B" --search 'pop rdi; ret'
ropper --file "$B" --search 'pop r??; ret'                # ? = any char, % = any substring
ropper --file "$B" --search '% syscall'
ropper --file "$B" --jmp 'rsp'                            # jmp rsp / call rsp gadgets
ropper --file "$B" --type jop                             # JOP gadgets
ropper --file "$B" --stack-pivot
ropper --file "$B" --chain execve                         # ropper's chain generator

# 7. gadgets in libc (where most of them live once you have a leak)
ROPgadget --binary ./libc.so.6 --only 'pop|ret' | grep 'pop rdi'
ropper --file ./libc.so.6 --search 'pop rdi; ret'

# 8. filter out gadgets containing bad bytes
ROPgadget --binary "$B" --badbytes '00|0a|20'
ropper --file "$B" --search 'pop rdi; ret' -b 000a20

# 9. machine-readable output for scripting
ROPgadget --binary "$B" --only 'pop|ret' --dump | head
ropper --file "$B" --search 'pop rdi' --console          # interactive session

# 10. pwntools does the same thing inside your exploit (usually the easiest)
python3 - <<'PY'
from pwn import *
exe = ELF("./chal", checksec=False)
rop = ROP(exe)
print(hex(rop.find_gadget(["pop rdi", "ret"])[0]))
print(hex(rop.find_gadget(["ret"])[0]))
rop.call("system", [next(exe.search(b"/bin/sh\x00"))])
print(rop.dump())
PY
```

The gadget shopping list for x86-64 Linux:

| Goal | Gadget |
|---|---|
| Set the 1st argument | `pop rdi ; ret` |
| Set the 2nd argument | `pop rsi ; ret` (often `pop rsi ; pop r15 ; ret`) |
| Set the 3rd argument | `pop rdx ; ret` (rare in small binaries - that is why ret2csu exists) |
| Set the syscall number | `pop rax ; ret` |
| Make a syscall | `syscall ; ret` or `syscall` |
| Stack alignment before `system` | a bare `ret` |
| Write to memory | `mov qword ptr [rdi], rsi ; ret` or `mov [rax], rdx ; ret` |
| Read from memory | `mov rax, qword ptr [rdi] ; ret` |
| Stack pivot | `leave ; ret`, `pop rsp ; ret`, `xchg rax, rsp ; ret`, `add rsp, N ; ret` |
| Zero a register | `xor rax, rax ; ret` |
| SROP trigger | `pop rax ; ret` (set to 15) + `syscall` |
| ret2csu | `pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` plus the `mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12+rbx*8]` sequence in `__libc_csu_init` |

32-bit x86 uses the stack for arguments, so you mostly need `ret` and the occasional `pop; pop; pop; ret` for cleanup. ARM/AArch64 gadgets end in `pop {..., pc}` / `ret` and load arguments into `r0-r3` / `x0-x7`.

## Gotchas

- **Gadget addresses are relative to the module base.** With PIE, add the leaked base. In libc, add `libc.address`.
- `--ropchain` only works when the binary is **static and non-PIE** and contains the right write primitives. It fails silently-ish on dynamic binaries - that is expected, not a bug.
- 16-byte stack alignment: on modern glibc, `system()` uses SSE instructions that fault if `rsp` is not 16-byte aligned at the call. If your `system("/bin/sh")` crashes inside `do_system`, insert a bare `ret` before it.
- Gadgets containing bad bytes (`\x00`, `\x0a`, `\x20`) will be truncated by `strcpy`/`gets`/`scanf`. Filter with `--badbytes`.
- Searching a large libc produces hundreds of thousands of gadgets; always grep or use `--only`.
- `--only 'pop|ret'` filters by instruction *type*, not by a regex on the whole line; combine with `grep` for exact matches.
- Unaligned gadgets (starting mid-instruction) are real and usable on x86, but can behave unexpectedly; verify in gdb.
- ropper and ROPgadget report the same gadgets in different formats; scripts that parse one will not parse the other.
- For very small overflows, do not search harder - pivot the stack or use a one_gadget instead.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You want gadgets in your exploit script | `pwntools`' `ROP` class - it finds and orders them for you |
| No gadgets in the binary | search libc after you have a leak; or `ret2dlresolve` if you have none |
| Chain does not fit | stack pivot, or `one_gadget` (`ctfbrain search one-gadget`) |
| Can't set rdx | `ret2csu`, or SROP (which sets every register at once) |
| Automatic exploit generation | `angrop` (angr's ROP chain builder), `ropium` |
| Gadget search inside gdb | pwndbg's `rop --grep`, GEF's `ropper` integration |
| Non-ELF or exotic architecture | `ropper` supports PE/Mach-O and more architectures than ROPgadget |
