---
title: "GDB for Reverse Engineering - Cheatsheet"
category: rev
subcategory: gdb
type: cheatsheet
tags: [gdb, debugger, watchpoints, breakpoints, dprintf, reverse-debugging, record, checkpoint, gdb-python, tui, disassemble, examine, gdbserver, gdb-multiarch, conditional-breakpoint, catchpoint]
summary: "gdb aimed at understanding a binary rather than exploiting it: watchpoints, conditional breaks, x/ formats, scripting and reverse execution."
tools: [gdb, gdbserver, gdb-multiarch, pwndbg, gef]
related: [dynamic-analysis-ltrace-ldpreload, anti-debug-bypass, side-channel-instruction-counting, radare2-cheatsheet, assembly-cheatsheet, binary-patching]
---

## Starting

```sh
# Load a binary without running it
gdb -q ./chall
# Pass arguments (everything after --args belongs to the program)
gdb -q --args ./chall -v input.txt
# Run a batch of commands and exit - the scripting workhorse
gdb -q -batch -ex 'break main' -ex run -ex 'info registers' ./chall
# Attach to a running process
gdb -q -p $(pgrep -n chall)
# Post-mortem with a core file
gdb -q ./chall core.1234
# Source a command file at startup
gdb -q -x commands.gdb ./chall
# Cross-architecture (ARM/MIPS binary under qemu-user)
qemu-arm -L /usr/arm-linux-gnueabihf -g 1234 ./chall &
gdb-multiarch -q -ex 'set architecture arm' -ex 'target remote :1234' ./chall
```

```
# Stop at the very first instruction (before the dynamic loader runs your code)
starti
# Stop at main (or the first user code, if main is not a symbol)
start
# Run to completion
run
# Run with a different argv without restarting gdb
run arg1 arg2
# Feed stdin from a file
run < input.txt
# Set an environment variable for the inferior only
set environment LD_PRELOAD ./hook.so
# Remove one gdb adds that anti-debug code looks for
unset env LINES
unset env COLUMNS
# Do not start the program under /bin/sh (avoids an extra process, and some checks)
set startup-with-shell off
# Follow the child on fork (anti-debug binaries fork and trace themselves)
set follow-fork-mode child
set detach-on-fork off
# Keep going when a signal arrives (int3/SIGTRAP-driven control flow)
handle SIGTRAP nostop noprint pass
handle SIGSEGV nostop noprint pass
```

## Breakpoints

```
# By symbol, by file:line, by raw address
break main
break chall.c:42
break *0x401136
# Address inside a PIE, after the program is running (use the runtime address)
break *($_base("chall") + 0x1136)
# Temporary: deleted after the first hit
tbreak *0x401136
# Regex over all symbol names - great for "break on anything named check*"
rbreak ^check
rbreak ^str(cmp|ncmp|len)$
# Hardware execution breakpoint: does not write 0xCC, invisible to breakpoint scanners
hbreak *0x401136
# Pending: set now, resolve when the library loads
set breakpoint pending on
break gcry_cipher_encrypt
# Conditional
break check if $rdi == 0
break *0x401150 if $rsi > 10
# Condition on a string argument (gdb's convenience function)
break strcmp if $_streq((char*)$rdi, "flag")
# Condition on a memory value
break *0x401200 if *(int*)($rbp-0x14) == 7
# Skip the first N hits
break memcpy
ignore 1 100
# Attach a command list - `silent` suppresses the usual breakpoint banner
break memcmp
commands
silent
printf "memcmp(%s, %s, %d)\n", (char*)$rdi, (char*)$rsi, $rdx
continue
end
# printf at an address with no stop at all (the cheapest tracing primitive)
dprintf *0x401180, "i=%d c=%c\n", $ebx, $al
dprintf check, "check(%s)\n", (char*)$rdi
# Syscall catchpoints - the way to intercept ptrace in a static binary
catch syscall ptrace
catch syscall mprotect
catch syscall write
# Other catchpoints
catch fork
catch exec
catch load libcrypto.so.3
catch throw
# Manage
info breakpoints
delete 3
disable 2
enable 2
condition 2 $rax == 0
```

## Watchpoints - the single most useful RE feature

```
# Break when a variable/address is written (hardware, 4 max on x86)
watch *(int*)0x404060
watch counter
# Watch a location, not an expression - survives scope changes
watch -l buf[3]
# Break when it is read
rwatch *(char*)0x404070
# Break on read or write
awatch *(long*)($rbp-0x18)
# Watch an expression: stops when the VALUE changes
watch $rax == 0
# Software watchpoint over a range (slow: single-steps) when hardware runs out
set can-use-hw-watchpoints 0
watch *buffer@64
# See which ones exist and how many hardware slots are used
info watchpoints
```

Typical use: you know the flag ends up in a buffer but not who writes it -
`watch *(char*)0x404060` then `continue` and read the backtrace.

## Examining memory and registers

```
# x/NFU ADDR : N = count, F = format, U = unit size
x/16xb $rsp          # 16 bytes in hex
x/8xw $rsp           # 8 words (4-byte)
x/4xg $rsp           # 4 giant words (8-byte)
x/s $rdi             # NUL-terminated string
x/3s 0x402010        # three consecutive strings
x/20i $pc            # 20 instructions from the program counter
x/i $pc              # just the next instruction
x/10dw &counter      # 10 signed decimal words
x/10uw &counter      # unsigned
x/16cb $rsi          # as characters
x/8tw $rax           # binary
x/4a $rsp            # as addresses, with symbol annotation
x/2f $xmm0           # floats
x/z 0x404060         # zero-padded hex
```

| Format letter | Meaning | | Size letter | Bytes |
|---|---|---|---|---|
| `x` | hex | | `b` | 1 |
| `d` | signed decimal | | `h` | 2 |
| `u` | unsigned decimal | | `w` | 4 |
| `o` | octal | | `g` | 8 |
| `t` | binary | | | |
| `a` | address + nearest symbol | | | |
| `c` | char | | | |
| `f` | float | | | |
| `s` | string | | | |
| `i` | instruction | | | |
| `z` | zero-padded hex | | | |

```
# Print expressions with a format
p/x $rax
p/d $eflags
p/t $al
p/c $al
p $rsp - $rbp
# C expressions work, including casts and dereferences
p *(struct sockaddr_in *)$rsi
p (char*)$rdi
p ((char*)$rdi)[3]
# Artificial arrays: print N elements of a pointer
p *buf@32
p *(char*)$rdi@16
p/x *(int*)0x404060@8
# Types
ptype struct sockaddr_in
ptype check
whatis $rdi
# Registers
info registers
info registers rax rbx
info all-registers            # includes xmm/ymm/st
p $eflags
p $_siginfo
# Set registers and memory
set $rax = 1
set $pc = 0x401150
set var counter = 0
set {int}0x404060 = 0x41414141
set {char[4]}0x404060 = "AAA"
```

## Information about the program

```
info functions             # all functions (regex arg supported: info functions ^check)
info variables             # all globals
info sharedlibrary         # loaded libraries and their load addresses
info proc mappings         # the memory map (like /proc/pid/maps)
info files                 # section addresses - what to pass to Ghidra as the base
info frame                 # current frame layout: saved rip, args, locals
info locals
info args
info symbol 0x401136       # which symbol is at this address
info line *0x401136        # which source line
info threads
info inferiors
info signals
maintenance info sections  # every section with flags
```

## Disassembly

```
# Intel syntax (do this first, every time)
set disassembly-flavor intel
# Disassemble the current function
disassemble
# With raw bytes and source interleaved
disassemble /rs
# A specific function or range
disassemble check
disassemble 0x401136, 0x401200
disassemble 0x401136, +64
# Mark the current instruction with =>
disassemble /r $pc, +32
```

## Stepping

```
stepi        / si        # one instruction, into calls
nexti        / ni        # one instruction, over calls
step         / s         # one source line, into calls
next         / n         # one source line, over calls
finish                   # run to the end of the current function, print the return value
until                    # like next, but does not go backwards in a loop
until 0x401180           # run until an address (skips loops)
advance check            # run until a location is reached, without a permanent breakpoint
jump *0x401200           # set pc and continue - skip a check entirely
return                   # pop the frame immediately
return 1                 # ... forcing a return value
call check("test")       # call a function in the inferior
p check("test")          # same, prints the result
continue 5               # continue, ignoring this breakpoint 4 more times
```

## Memory dump and search

```
# Write a memory range to a file (unpacking, extracting a decoded buffer)
dump binary memory out.bin 0x404000 0x405000
dump binary value out.bin *(char(*)[256])$rdi
# Read it back into the process
restore out.bin binary 0x404000
# Search memory
find 0x400000, 0x410000, "CTF{"
find /w 0x404000, 0x405000, 0xdeadbeef
find /b 0x400000, +0x10000, 0x90, 0x90, 0x90
# Dump all of the heap after locating it
info proc mappings
dump binary memory heap.bin 0x405000 0x426000
```

## Reverse debugging and checkpoints

```
# Record every instruction so you can step backwards ("time travel")
record full
# Bound the log (default 200000 instructions)
set record full insn-number-max 2000000
# Go backwards
reverse-stepi        / rsi
reverse-nexti        / rni
reverse-step
reverse-next
reverse-finish
reverse-continue
# Watchpoints work in reverse: THE way to answer "who corrupted this?"
watch *(int*)0x404060
reverse-continue
# Stop recording, show statistics
record stop
info record
# Save/restore the recorded execution
record save mytrace
record restore mytrace

# Checkpoints (fork-based snapshots) - cheaper than record for "try it both ways"
checkpoint
info checkpoints
restart 1
delete checkpoint 1
```

Reverse execution is slow (roughly 100x) but priceless when you have to answer
"what wrote this value" in a program you do not understand.

## Useful settings and a .gdbinit

```
set disassembly-flavor intel
set pagination off
set confirm off
set print pretty on
set print asm-demangle on
set print object on
set print array on
set print elements 0          # do not truncate long strings/arrays
set print repeats 0
set disable-randomization on  # default on; turn OFF to mimic a real run
set follow-exec-mode same
set max-value-size unlimited
set history save on
set history size 10000
set logging file gdb.log
set logging enabled on        # (older gdb: set logging on)
```

```sh
# ~/.gdbinit or a per-project ./commands.gdb
cat > commands.gdb <<'EOF'
set disassembly-flavor intel
set pagination off
define hook-stop
  x/4i $pc
  info registers rax rbx rcx rdx rsi rdi
end
define cmpwatch
  dprintf memcmp, "memcmp(%s, %s, %d)\n", (char*)$rdi, (char*)$rsi, $rdx
  dprintf strcmp, "strcmp(%s, %s)\n", (char*)$rdi, (char*)$rsi
end
document cmpwatch
Log every memcmp/strcmp without stopping. Usage: cmpwatch, then run.
EOF
gdb -q -x commands.gdb ./chall
```

## TUI

```
layout asm                 # disassembly window
layout regs                # registers window (combine with asm)
layout split               # source + asm
tui enable                 # (or Ctrl-X A to toggle)
focus cmd                  # which pane the arrow keys scroll
focus asm
winheight asm +5
tui reg general            # switch the register group shown
refresh                    # redraw after output corruption
```

## Python scripting

```
# One-liners
python print(gdb.execute("info registers rax", to_string=True))
python print(hex(int(gdb.parse_and_eval("$rsp"))))
python gdb.execute("break main")
# Read raw memory
python print(bytes(gdb.selected_inferior().read_memory(0x404060, 32)))
# Write memory
python gdb.selected_inferior().write_memory(0x404060, b"AAAA")
# Source a script
source hook.py
```

```python
#!/usr/bin/env python3
"""cmplog.py - log every strcmp/memcmp argument pair without stopping.

    gdb -q -x cmplog.py ./chall
    (gdb) run

This is the single highest-value gdb script for crackmes: the expected value is
whatever the program compares your input against.
"""
try:
    import gdb  # type: ignore
except ImportError:
    gdb = None


def cstring(addr: int, limit: int = 64) -> str:
    """Read a NUL-terminated string from the inferior, safely."""
    try:
        inferior = gdb.selected_inferior()
        raw = bytes(inferior.read_memory(addr, limit))
    except Exception:
        return "<unreadable>"
    return raw.split(b"\x00")[0].decode("utf-8", errors="replace")


class CompareLogger(gdb.Breakpoint if gdb else object):
    """Break on a comparison function, print both operands, and keep going."""

    def __init__(self, symbol: str, kind: str):
        super().__init__(symbol)
        self.silent = True
        self.kind = kind
        self.hits = 0

    def stop(self) -> bool:
        frame = gdb.selected_frame()
        arg1 = int(frame.read_register("rdi"))
        arg2 = int(frame.read_register("rsi"))
        self.hits += 1
        if self.kind == "mem":
            size = int(frame.read_register("rdx"))
            left = bytes(gdb.selected_inferior().read_memory(arg1, min(size, 64)))
            right = bytes(gdb.selected_inferior().read_memory(arg2, min(size, 64)))
            print(f"[{self.hits:03d}] memcmp({left!r}, {right!r}, {size})")
        else:
            print(f"[{self.hits:03d}] strcmp({cstring(arg1)!r}, {cstring(arg2)!r})")
        return False          # never halt


def install() -> None:
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set disassembly-flavor intel")
    for sym, kind in (("strcmp", "str"), ("strncmp", "str"), ("strcasecmp", "str"),
                      ("memcmp", "mem"), ("bcmp", "mem")):
        try:
            CompareLogger(sym, kind)
            print(f"[cmplog] hooked {sym}")
        except gdb.error:
            pass


if gdb is not None:
    install()
else:
    print("cmplog.py is a gdb script: gdb -q -x cmplog.py ./chall")
```

```python
#!/usr/bin/env python3
"""icount.py - add a `countinsn` command that single-steps and counts instructions.

    gdb -q -x icount.py ./chall
    (gdb) break *0x401136
    (gdb) run
    (gdb) countinsn 0x401200        # count instructions until this address is reached

Useful as a precise, noise-free oracle for side-channel byte-by-byte attacks on
small functions (see side-channel-instruction-counting).
"""
try:
    import gdb  # type: ignore
except ImportError:
    gdb = None


class CountInsn(gdb.Command if gdb else object):
    """countinsn [stop_address] [max_steps] - single-step and count instructions."""

    def __init__(self):
        super().__init__("countinsn", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        parts = arg.split()
        stop_at = int(parts[0], 0) if parts else None
        limit = int(parts[1], 0) if len(parts) > 1 else 1_000_000
        count = 0
        gdb.execute("set pagination off")
        while count < limit:
            pc = int(gdb.parse_and_eval("$pc"))
            if stop_at is not None and pc == stop_at:
                break
            try:
                gdb.execute("stepi", to_string=True)
            except gdb.error as exc:
                print(f"[icount] stopped: {exc}")
                break
            count += 1
        print(f"[icount] {count} instructions executed")


if gdb is not None:
    CountInsn()
    print("[icount] `countinsn <addr>` registered")
else:
    print("icount.py is a gdb script: gdb -q -x icount.py ./chall")
```

## Remote and cross-architecture

```sh
# Server side
gdbserver :1234 ./chall
gdbserver :1234 --attach $(pgrep -n chall)
# Client side
gdb-multiarch -q ./chall
```

```
target remote 127.0.0.1:1234
target extended-remote 127.0.0.1:1234
set architecture aarch64
set sysroot /usr/aarch64-linux-gnu
set solib-search-path ./libs
detach
monitor help                 # pass a command to the stub (gdbserver/qemu/openocd)
```

```sh
# qemu-user: -g starts a gdb stub before the first instruction
qemu-mipsel -L /usr/mipsel-linux-gnu -g 1234 ./chall &
gdb-multiarch -q -ex 'set architecture mips' -ex 'target remote :1234' ./chall
# qemu-system for firmware; OpenOCD for real hardware
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg      # then target remote :3333
```

## Plugin commands worth knowing (pwndbg / gef)

```
# pwndbg
vmmap                  # memory map with permissions and module names
telescope $rsp 20      # dereference chains from the stack
hexdump 0x404060 64
nearpc 20
context               # re-print the full context view
procinfo
got / plt             # resolved GOT and PLT entries
search --string "CTF{"
xinfo 0x404060        # everything about an address
# gef
vmmap
xinfo 0x404060
scan libc stack       # find pointers from one region into another
pattern create 100
heap chunks
```

Both also make `break`, `x/`, `watch` behave identically - the plugins add views, not new
semantics.

## Quick recipes

```sh
# 1. What does this binary compare my input to?
gdb -q -batch -ex 'set pagination off' -ex 'break strcmp' \
    -ex 'commands' -ex 'silent' -ex 'x/s $rsi' -ex 'continue' -ex 'end' \
    -ex 'run <<< AAAA' ./chall

# 2. Dump a decoded buffer after an unpacking loop finishes
gdb -q -batch -ex 'break *0x401337' -ex run \
    -ex 'dump binary memory decoded.bin 0x404000 0x405000' ./chall

# 3. Skip an anti-debug check entirely
gdb -q -ex 'catch syscall ptrace' -ex run -ex 'set $rax = 0' -ex continue ./chall

# 4. Find who writes a global
gdb -q -ex 'break main' -ex run -ex 'watch *(int*)0x404060' -ex continue -ex bt ./chall

# 5. Trace every call made by the program (noisy but complete)
gdb -q -batch -ex 'set pagination off' -ex 'rbreak .' \
    -ex 'commands' -ex 'silent' -ex 'bt 1' -ex 'continue' -ex 'end' -ex run ./chall
```

## References

- The GDB manual, chapters "Setting Watchpoints", "Examining Memory", "Reverse Execution",
  "Extending GDB / Python API".
- `gdb` online help: `help breakpoints`, `help x`, `help record`, `apropos watch`.
