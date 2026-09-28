---
title: "Tool - gdb with pwndbg / GEF"
category: pwn
subcategory: debugger
type: tool
tags: [gdb, pwndbg, gef, peda, debugger, breakpoint, heap, vmmap, checksec, telescope, pattern, watchpoint, pwn, rev, attach, gdbinit]
summary: "The debugger, plus the exploit-development plugins that make it show you the heap, the registers and the memory layout at a glance."
related: [pwn-triage, pwntools, ropgadget-ropper, one-gadget]
---

## What it is

`gdb` with an exploitation plugin is where you confirm every assumption in a pwn challenge: the exact offset to the return address, the heap layout after each `free`, the value of a leak, and whether a one_gadget's constraints hold. **pwndbg** and **GEF** are the two maintained plugins; pick one (installing both causes conflicts).

## Install

```sh
# pwndbg (recommended for heap work)
git clone --depth 1 https://github.com/pwndbg/pwndbg && ./pwndbg/setup.sh
# GEF (single file, zero dependencies)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/hugsy/gef/main/scripts/gef.sh)"
# or manually:
#   echo "source /path/to/gef.py" >> ~/.gdbinit
# macOS: gdb is awkward; use lldb, or run Linux in Docker/UTM
brew install gdb          # then codesign it, or just use a Linux container
# verify
gdb -q -ex 'pi print("ok")' -ex quit
```
`~/.gdbinit` should source exactly one plugin. Switch by commenting the other out.

## The invocations that matter

```sh
# 1. start with the binary, break at main, run
gdb -q ./chal -ex 'b main' -ex run

# 2. feed stdin from a command without a shell wrapper
gdb -q ./chal -ex 'r < <(python3 -c "import sys; sys.stdout.buffer.write(b\"A\"*200)")'

# 3. attach to a running process
gdb -q -p $(pgrep -f chal)

# 4. attach to a process started by pwntools (the normal workflow)
#    in the exploit:  io = gdb.debug("./chal", gdbscript="b *main+42\nc")
#    or:              gdb.attach(io, "b *0x401234\nc")

# 5. run with the provided libc/loader
gdb -q --args ./ld-2.31.so --library-path . ./chal

# 6. debug a core dump
ulimit -c unlimited && ./chal; gdb -q ./chal core

# 7. a scripted, non-interactive run
gdb -q -batch -ex 'b *0x401234' -ex run -ex 'x/16gx $rsp' -ex 'info registers' ./chal

# 8. disable ASLR (gdb does this by default; this turns it back on)
gdb -q ./chal -ex 'set disable-randomization off'

# 9. follow a forked child
gdb -q ./chal -ex 'set follow-fork-mode child' -ex 'set detach-on-fork off'

# 10. load a gdbscript file
gdb -q -x solve.gdb ./chal
```

Core gdb commands:

| Command | Meaning |
|---|---|
| `b main`, `b *0x401234`, `b file.c:42` | breakpoints |
| `b *$rebase(0x1234)` | breakpoint on a PIE offset (pwndbg/GEF) |
| `tb` | temporary breakpoint |
| `rwatch`/`watch`/`awatch <expr>` | read/write/access watchpoints - the fastest way to find who corrupts a value |
| `r`, `c`, `n`, `s`, `ni`, `si`, `fin` | run, continue, next, step, next-instr, step-instr, finish |
| `x/16gx $rsp` | examine 16 giant (8-byte) hex values at rsp |
| `x/s $rdi`, `x/20i $rip`, `x/64bx addr` | string, instructions, bytes |
| `p $rax`, `p/x $rax`, `p *(long*)($rbp-8)` | print |
| `set $rax = 0`, `set {long}0x404040 = 1` | modify registers and memory |
| `i r`, `i f`, `i b`, `i proc mappings` | info registers/frame/breakpoints/maps |
| `bt`, `frame N` | backtrace, switch frame |
| `disas main`, `disas /s` | disassemble |
| `set disassembly-flavor intel` | readable syntax (put it in `~/.gdbinit`) |
| `define hook-stop ... end` | run commands on every stop |
| `commands N ... end` | run commands when breakpoint N hits |

pwndbg / GEF additions:

| Command | Meaning |
|---|---|
| `checksec` | protections of the loaded binary |
| `vmmap` | memory map with permissions; find the libc/heap/stack base |
| `telescope $rsp 20` (pwndbg) / `dereference $rsp 20` (GEF) | dereference a chain of pointers - the best stack view |
| `heap` | heap chunk listing |
| `bins` | tcache/fastbin/unsorted/small/large contents |
| `vis` / `vis_heap_chunks` (pwndbg) | annotated visual heap dump |
| `arena` / `heap chunks` (GEF) | arena state |
| `cyclic 200` / `pattern create 200` | generate a De Bruijn pattern |
| `cyclic -l 0x6161616161616166` / `pattern search` | find the offset |
| `got`, `plt` | GOT/PLT tables with current values |
| `search -t string "flag"` / `grep flag` | search memory |
| `p2p`, `pointers` | pointer-to-pointer search |
| `ropper`/`rop --grep 'pop rdi'` | gadget search inside gdb |
| `canary` | print the current stack canary |
| `libc` / `libcbase` | libc base address |
| `context` | redraw the register/stack/code/backtrace panes |
| `nextcall`, `nextret`, `stepover` | navigation helpers |
| `tele-heap`, `xinfo <addr>` | what is this address |

The offset-finding workflow:
```sh
gdb -q ./chal
pwndbg> cyclic 200
pwndbg> r
# paste the pattern, let it crash
pwndbg> i r rsp            # or look at the faulting address
pwndbg> cyclic -l 0x6161616161616166
# -> "Found at offset 72"
```

## Gotchas

- **gdb disables ASLR by default.** Addresses you see are not what the remote sees. Use offsets from a module base, never absolute values.
- The stack layout differs between gdb and a normal shell because the environment differs. `env -i ./chal` gets closer, but never rely on a stack address found in gdb.
- pwndbg and GEF **conflict**. `~/.gdbinit` must source only one.
- `b *0x1234` on a PIE binary breaks at a file offset before the program is mapped. Either `start` first, or use `b *$rebase(0x1234)`.
- `heap`/`bins` need libc debug symbols to be fully accurate. Install `libc6-dbg` or use `pwndbg`'s heuristic mode.
- If gdb cannot find the right libc when you patched the binary with `patchelf`, `set sysroot .` and `set solib-search-path .`.
- `gdb.attach()` from pwntools needs `context.terminal` set (e.g. `["tmux", "splitw", "-h"]`) or it does nothing silently.
- On a `ptrace`-protected binary, gdb will fail to attach: patch the `ptrace` call or `LD_PRELOAD` a stub.
- macOS gdb requires code signing and generally does not work well; use a Linux container for pwn.
- `set follow-fork-mode child` is essential for forking network services, or you debug the idle parent.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| macOS native debugging | `lldb` (different commands, same ideas) |
| Windows binaries | `x64dbg`, WinDbg |
| You want scripting over UI | pwntools + `gdb.debug(gdbscript=...)`, or `gdb -batch -ex` |
| Kernel debugging | `gdb` attached to QEMU's gdbstub (`-s -S`) |
| Tracing rather than stepping | `ltrace`, `strace`, `perf`, Frida |
| Heap visualisation elsewhere | `heaptrace`, `libheap`, or pwndbg's `vis` |
| No debugger available on target | add prints, or use `ptrace`-free instrumentation |
