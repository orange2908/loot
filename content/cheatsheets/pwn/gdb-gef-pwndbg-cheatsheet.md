---
title: "GDB + GEF + pwndbg - Side-by-Side Debugging Cheatsheet"
category: pwn
subcategory: tooling
type: cheatsheet
tags: [gdb, gef, pwndbg, checksec, vmmap, telescope, heap, got, plt, pattern, cyclic, gdbserver, qemu, core-dump, aslr, pie, canary, relro, nx, pwntools]
summary: "Every gef command next to its pwndbg equivalent: vmmap, telescope, heap, got/plt, patterns, breakpoints, core dumps, gdbserver and qemu remote."
tools: [gdb, gef, pwndbg, gdbserver, qemu-user, gdb-multiarch, pwntools]
related: [pwntools-cheatsheet, rop-gadgets-cheatsheet, offset-finder, exploit-template, stack-buffer-overflow-basics, mitigation-canary-bypass]
---

## Install

```bash
# gef - single file, drops into ~/.gdbinit
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# pwndbg - clone and run setup.sh
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Keep both, switch per session (do NOT source both at once)
cat > ~/.gdbinit <<'EOF'
# source ~/.gdbinit-gef.py
# source /path/to/pwndbg/gdbinit.py
EOF
gdb -q -ex 'source ~/.gdbinit-gef.py' ./vuln
gdb -q -ex 'source ~/pwndbg/gdbinit.py' ./vuln

# Multi-arch gdb for ARM/MIPS targets
sudo apt install gdb-multiarch qemu-user qemu-user-static
```

## Starting gdb

```bash
gdb -q ./vuln                       # quiet, no banner
gdb -q --args ./vuln arg1 arg2      # with argv
gdb -q ./vuln core                  # load a core dump
gdb -q -p 12345                     # attach to a running pid
gdb -q -ex 'b main' -ex 'run' ./vuln
gdb -q -x ./script.gdb ./vuln       # batch script
gdb -q -batch -ex 'info functions' ./vuln   # one-shot, exit after
gdb-multiarch -q ./vuln             # non-native arch
```

```gdb
# Inside gdb
file ./vuln
run
run < input.bin
run $(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*100)')
set args AAAA BBBB
start                        # break at main and run
starti                       # stop at the very first instruction (_start)
attach 12345
detach
kill
quit
```

## Process info / security properties

```gdb
# gef
checksec
vmmap
vmmap libc
aslr                          # show ASLR state
aslr off                      # disable for the child
got
got puts
canary                        # print the current canary value
elf-info
entry-break

# pwndbg
checksec
vmmap
vmmap libc
piebase                       # PIE load base
got
got puts
plt
canary
elfheader
entry
```

```gdb
# Vanilla gdb equivalents
info proc mappings
info files
info functions
info variables
info sharedlibrary
info registers
info frame
info breakpoints
info threads
info inferiors
p $_siginfo
shell cat /proc/$(pgrep -n vuln)/maps
```

## Memory display

```gdb
# gef
telescope $rsp 20            # dereferencing stack view
telescope $rsp 20 -l 4
dereference $rbp
hexdump byte 0x404000 64
hexdump qword $rsp 16
xinfo 0x7ffff7a52290         # what IS this address
grep /bin/sh                 # search all mapped memory
search-pattern "/bin/sh"
search-pattern 0xdeadbeef
search-pattern "AAAA" little libc

# pwndbg
telescope $rsp 20
telescope 0x404000
dq $rsp 20                   # qwords
dd $rsp 20                   # dwords
dw / db / ds                 # words / bytes / strings
hexdump 0x404000 64
search /bin/sh
search -t qword 0xdeadbeef
search --string "flag{"
probeleak $rsp 0x100         # find pointers in a region
```

```gdb
# Vanilla
x/20gx $rsp                  # 20 giant (8-byte) hex
x/20wx $esp                  # 20 word (4-byte) hex
x/s 0x404050                 # C string
x/20i $rip                   # 20 instructions
x/10dw &counter              # decimal words
p/x $rax
p (char*)0x404050
p *(unsigned long*)($rbp-8)
dump binary memory out.bin 0x404000 0x405000
restore in.bin binary 0x404000
find 0x400000, 0x500000, "/bin/sh"
find /w 0x400000, +0x1000, 0xdeadbeef
```

## Registers and flow

```gdb
info registers
info registers rax rbx
p $rsp
p/x $eflags
set $rax = 0
set $rip = 0x401234
set var counter = 5
set {int}0x404050 = 0x41414141
set {char[8]}$rsp = "AAAAAAA"

# gef
registers
context regs
flags
flags +zero                  # set ZF
flags -carry

# pwndbg
regs
context regs
setflag ZF 1
```

```gdb
ni                           # step over one instruction
si                           # step into one instruction
n / s                        # source-level next / step
c                            # continue
finish                       # run until the current frame returns
until 0x401250
advance vuln
return                       # force-return from the frame
jump *0x401234
stepi 10
bt                           # backtrace
bt full
frame 2
up / down
```

## Breakpoints and watchpoints

```gdb
b main
b *0x401234                  # exact address
b *main+42                   # offset into a symbol
b vuln.c:31
b puts                       # libc function by name
b *puts                      # first instruction of puts (skip the PLT thunk)
b system
b execve
b __libc_start_main
b strcpy if $rdx > 100
tbreak main                  # temporary, deletes after hit
rbreak ^str.*                # regex break on every matching symbol

# PIE: rebase at runtime
b *$rebase(0x1234)           # gef and pwndbg both provide $rebase
p $_base()                   # pwndbg
pie break 0x1234             # pwndbg's pie-aware breakpoints
pie b *0x1234

watch counter                # write watchpoint
rwatch counter               # read watchpoint
awatch counter               # either
watch *(unsigned long*)0x404050
watch -l buf[3]

info breakpoints
delete 2
disable 3
enable 3
condition 1 $rdi == 0x404050
ignore 1 5                   # skip the next 5 hits

commands 1
    telescope $rsp 10
    continue
end
```

## Context display

```gdb
# gef
context
context regs stack code
gef config context.layout "legend regs stack code args source memory threads trace extra"
gef config context.nb_lines_stack 16
gef config context.grow_stack_down True
gef config theme.dereference_base_address blue
gef save                     # persist config to ~/.gef.rc

# pwndbg
context
context regs
context stack
context code
context disasm
context backtrace
set context-sections "regs disasm code stack backtrace"
set context-stack-lines 16
nearpc 20
u main                       # disassemble
ctx                          # short alias
```

## Heap (both have full glibc heap support)

```gdb
# gef
heap chunks
heap chunk 0x4052a0
heap bins
heap bins tcache
heap bins fast
heap bins unsorted
heap bins small
heap bins large
heap arenas
heap set-arena 0x7ffff7dcfb80

# pwndbg
heap
heap -v
malloc_chunk 0x4052a0
bins
tcachebins
fastbins
unsortedbin
smallbins
largebins
arena
arenas
top_chunk
vis_heap_chunks              # the killer visualiser
vis 10
find_fake_fast 0x7fffffffe000
try_free 0x4052a0            # simulate free() and report which check fails
```

## Patterns / crash offsets

```gdb
# gef
pattern create 200
pattern create 200 -n 8
pattern search 0x6161616161616164
pattern search $rsp
pattern search "aaaaaaab"

# pwndbg
cyclic 200
cyclic -n 8 200
cyclic -l 0x6161616161616164
cyclic -l $rsp

# After a SIGSEGV, this is the whole workflow:
#   r <<< $(pattern create 200)
#   pattern search $rsp
```

## ROP / gadgets from inside gdb

```gdb
# gef
ropper --search "pop rdi"
ropper --search "pop r?i; ret"
ropper --jmp rsp
ropper --search "syscall"

# pwndbg
rop --grep 'pop rdi'
ropper                       # passes through to ropper
rop
```

```gdb
# Both: raw instruction search across mapped executable memory
search -t bytes 5fc3         # pop rdi ; ret
search -t bytes 0f05c3       # syscall ; ret
```

## Fork servers and multi-process

```gdb
set follow-fork-mode child       # follow the child (typical for fork servers)
set follow-fork-mode parent
set detach-on-fork off           # keep BOTH inferiors under control
info inferiors
inferior 2
set follow-exec-mode new
catch fork
catch exec
catch syscall execve
catch syscall 59                 # execve on amd64
catch syscall write
set scheduler-locking on         # freeze other threads while stepping
```

## Signals

```gdb
handle SIGSEGV stop print
handle SIGALRM nostop noprint pass     # kill noisy alarms in CTF binaries
handle SIGTRAP nostop noprint
info signals
signal SIGCONT
```

## Core dumps

```bash
# Enable cores and stop apport/systemd from swallowing them
ulimit -c unlimited
cat /proc/sys/kernel/core_pattern
echo 'core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern
sudo sysctl -w kernel.core_pattern=core
sudo systemctl stop apport.service 2>/dev/null

# Produce a core from the outside
gcore 12345
kill -SIGABRT 12345
```

```gdb
gdb -q ./vuln core.vuln.12345
core-file ./core
bt
info registers
x/40gx $rsp
p $rip
generate-core-file           # dump a core from inside gdb
gcore /tmp/my.core
```

```python
# pwntools reads cores directly - no gdb needed
from pwn import *
io = process('./vuln'); io.sendline(cyclic(300, n=8)); io.wait()
core = io.corefile
print(hex(core.rsp), hex(core.rip))
print(cyclic_find(core.read(core.rsp, 8), n=8))
print(core.maps)                 # memory map at crash time
print(core.stack.start)
print(core.getenv('PATH'))       # environment as it was on the stack
```

## Remote debugging: gdbserver

```bash
# Target side
gdbserver 0.0.0.0:1234 ./vuln
gdbserver 0.0.0.0:1234 --attach 12345
gdbserver --multi 0.0.0.0:1234        # then `target extended-remote` + `run`
```

```gdb
# Debugger side
target remote 127.0.0.1:1234
target extended-remote 127.0.0.1:1234
set sysroot /path/to/rootfs
set solib-search-path ./libs
file ./vuln                           # load symbols locally
add-symbol-file ./libc.so.6 0x7ffff7a00000
monitor exit
disconnect
```

## Remote debugging: qemu-user (ARM / AArch64 / MIPS)

```bash
# Run the foreign binary, wait for a debugger on :1234
qemu-arm      -L /usr/arm-linux-gnueabihf     -g 1234 ./vuln
qemu-aarch64  -L /usr/aarch64-linux-gnu       -g 1234 ./vuln
qemu-mips     -L /usr/mips-linux-gnu          -g 1234 ./vuln
qemu-mipsel   -L /usr/mipsel-linux-gnu        -g 1234 ./vuln

# Plain run (no debugger)
qemu-aarch64 -L /usr/aarch64-linux-gnu ./vuln
```

```gdb
gdb-multiarch -q ./vuln
set architecture arm
set architecture aarch64
set architecture mips
set endian little
target remote localhost:1234
b main
c
```

```python
# pwntools can drive qemu for you
from pwn import *
context.binary = './vuln'                  # sets arch from the ELF header
io = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu', './vuln'])
io = gdb.debug('./vuln', gdbscript='b main\nc')   # uses qemu automatically when arch != host
```

## Useful .gdbinit settings

```gdb
set disassembly-flavor intel
set follow-fork-mode child
set pagination off
set confirm off
set print pretty on
set print elements 0
set print repeats 0
set history save on
set history size 10000
set history filename ~/.gdb_history
set disable-randomization on      # default ON in gdb; turn OFF to test real ASLR
set disable-randomization off
set environment LD_PRELOAD ./libc.so.6
set env LINES 50
unset env LINES
set backtrace past-main on
set max-value-size unlimited
```

## Scripting

```gdb
define stack
    telescope $rsp 20
end
document stack
Dump 20 stack slots.
end

define hook-stop
    context
end

python
import gdb
rsp = int(gdb.parse_and_eval('$rsp'))
print(hex(rsp))
gdb.execute('x/8gx $rsp')
end
```

```bash
# Non-interactive one-liners
gdb -q -batch -ex 'b *main+42' -ex run -ex 'x/20gx $rsp' ./vuln
gdb -q -batch -ex 'info functions' ./vuln | grep -i win
gdb -q -batch -ex 'disassemble main' ./vuln
gdb -q -batch -ex 'p (char*)&flag' ./vuln
```

## Quick recipes

```text
# Where does my input land?
b *vuln+<offset_of_ret>  ->  telescope $rsp 30  ->  find your cyclic bytes

# What is the canary for this run?
gef:    canary
pwndbg: canary
plain:  p/x *(unsigned long*)($rbp-8)   (x86-64, typical layout)

# What is the PIE base right now?
gef:    vmmap | head
pwndbg: piebase
plain:  info proc mappings | head -3

# What libc is loaded and where?
vmmap libc   ->  base = first r-x/r-- line of libc

# Does my ROP chain survive?
b *<addr_of_ret_in_vuln>, then `si` one gadget at a time watching rsp/rip

# Stack alignment before a libc call (movaps crash)
at the `call system` instruction, check ($rsp & 0xf) == 0
```
