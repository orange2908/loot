---
title: "Kernel Mitigations - SMEP, SMAP, KPTI, KASLR and kCFI"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, smep, smap, kpti, kaslr, kcfi, cfi-clang, cr4, ret2usr, krop, fg-kaslr, kptr-restrict, dmesg-restrict, modprobe-path, qemu, pwndbg, gef]
difficulty: medium
summary: "What each kernel mitigation actually blocks, how to detect it from inside the VM, and which exploit strategy it forces you into."
when_to_use:
  - "You need to decide between ret2usr, kernel ROP, and a data-only attack"
  - "The run.sh has `+smep,+smap` and `pti=on` and you need to know what still works"
  - "Your exploit works with nokaslr but not with kaslr"
  - "An indirect call to a gadget panics with a CFI failure"
tools: [qemu, gdb, pwndbg, gef]
related: [kernel-setup-and-debug, kernel-ret2usr-creds, kernel-rop-kpti-trampoline, kernel-modprobe-path, kernel-pwn-cheatsheet]
---

## TL;DR

SMEP stops you executing user pages from the kernel. SMAP stops you *reading* them.
KPTI makes returning to user space require a specific trampoline. KASLR hides the
addresses. kCFI constrains where an indirect call may land. Each one removes a class
of technique, and the answer to all of them at once is a **data-only** attack -
overwrite `modprobe_path`.

## Recognise it

- `run.sh` has `-cpu qemu64,+smep,+smap` and `-append "... kaslr pti=on"`.
- Jumping to a user-space function panics with
  `unable to execute userspace code (SMEP?)` -> SMEP.
- Reading a user pointer from kernel context panics in `copy_from_user`-free code
  -> SMAP.
- Returning to user space triple faults instead of running your shell -> KPTI.
- Symbol addresses differ between boots -> KASLR.
- An indirect call panics with `CFI failure` in dmesg -> kCFI.

## Vulnerable code shape

Not a code shape - a configuration. Detect it at runtime:

```c
/* Read CR4 indirectly: you cannot MOV from CR4 in ring 3.
 * Instead, read the boot config the kernel exposes. */
static int has_flag_in_cpuinfo(const char *flag)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    char line[4096];
    int found = 0;
    if (!f) return -1;
    while (fgets(line, sizeof line, f))
        if (strncmp(line, "flags", 5) == 0 && strstr(line, flag)) { found = 1; break; }
    fclose(f);
    return found;
}
```

## Theory

### SMEP - Supervisor Mode Execution Prevention (CR4 bit 20)

The CPU faults if ring 0 tries to execute a page with the User bit set. That kills
**ret2usr**: you can no longer point a corrupted kernel function pointer at a userland
function that calls `commit_creds(prepare_kernel_cred(0))`.

What it forces: kernel ROP (gadgets from kernel `.text`), or a data-only attack.

Historic bypass: overwrite CR4 by ROP-calling `native_write_cr4(0x6f0)` to clear bit
20. Dead since Linux 4.15, which pins the SMEP/SMAP/UMIP bits:
`native_write_cr4` ORs the pinned bits back in and WARNs.

Detect: `grep -o smep /proc/cpuinfo | head -1`, or `p/x $cr4` in gdb
(bit 20 = `0x100000`).

### SMAP - Supervisor Mode Access Prevention (CR4 bit 21)

Ring 0 faults on *reads and writes* of user pages, unless it goes through the
`stac`/`clac`-wrapped accessors (`copy_from_user` and friends). That kills the
"fake structure in userland" pattern: your fake `tty_operations`, your fake stack for a
pivot, your ROP chain at a fixed mmap'd address - none of them are readable.

What it forces: everything the kernel must read has to live in **kernel** memory:

- `msg_msg` / `setxattr` / `sendmsg(MSG_MORE)` / `add_key` sprays put attacker-chosen
  bytes into kernel heap objects.
- The **physmap** (`0xffff888000000000` onwards) is a direct map of all physical RAM,
  so user pages *do* have kernel-visible aliases. Spray user pages, guess a physmap
  address, and the kernel can read them. Works well with a lot of RAM.
- Pivot the kernel stack into a kernel heap object rather than a user page.

Detect: `grep -o smap /proc/cpuinfo`, or `$cr4 & 0x200000`.

### KPTI - Kernel Page Table Isolation

Two sets of page tables: while in user mode, only a tiny trampoline of the kernel is
mapped. If you `iretq` back to user space from a ROP chain without switching CR3, the
return lands on unmapped memory and the CPU triple faults (the VM just reboots).

What it forces: end your ROP chain with the kernel's own return path,
`swapgs_restore_regs_and_return_to_usermode`, entered *after* its initial pops. See
`kernel-rop-kpti-trampoline`. Alternatives: a `signal` return that the kernel performs
for you, or simply never returning to user space (do everything in kernel land, e.g.
`modprobe_path`).

Detect: `dmesg | grep -i 'page table isolation'`, or the `pti=on` / `nopti` boot flag,
or `cat /sys/devices/system/cpu/vulnerabilities/meltdown`.

### KASLR - Kernel Address Space Layout Randomization

The kernel text base is randomised at boot with 2 MB granularity (so the low 21 bits of
`_text` are fixed, which is only ~9 bits of entropy in practice on many builds).
Modules are randomised separately. FG-KASLR (function-granular) additionally shuffles
individual functions inside `.text`, which breaks offset-based gadget hunting.

What it forces: leak the base before using any address. Sources:

| source | availability |
|--------|--------------|
| `/proc/kallsyms` | only with `kptr_restrict=0`, usually root-only |
| `dmesg` | only with `dmesg_restrict=0`; oops messages contain `RIP: 0010:func+0x..` |
| `/sys/kernel/notes` | sometimes world readable |
| `/proc/self/stat` field 30-32 | kernel stack pointers on ancient kernels |
| an info-leak primitive | the intended route: an OOB read of a `seq_operations` or `tty_struct` pointer |
| `prctl`/`perf` side channels | out of scope for CTF |

Once you have any kernel text pointer, `kbase = leaked - known_offset_of_that_symbol`,
and the offsets come from your extracted `vmlinux`.

Detect: boot twice and compare `cat /proc/kallsyms | head -1` (as root), or check the
`nokaslr` boot flag.

### kCFI / CONFIG_CFI_CLANG

Every indirect call is preceded by a check that the target's prologue contains the
type hash of the expected function type. Landing on a random `pop rdi; ret` gadget via
an indirect call is now a `CFI failure` panic.

What it forces:

- Function-pointer overwrites must target a function with the *same* type signature
  (e.g. replace one `tty_operations->ioctl` with another `.ioctl`).
- ROP via a **return** is unaffected (kCFI only guards forward edges); so a stack pivot
  plus `ret`-chaining still works unless shadow stacks / IBT are also on.
- Data-only attacks are unaffected entirely.

Detect: `dmesg | grep -i cfi`, or look for `__cfi_` prefixed symbols in `vmlinux`.

### The rest of the switchboard

| sysctl | effect |
|--------|--------|
| `kernel.kptr_restrict` | 0 = `/proc/kallsyms` shows real addresses, 1/2 = zeros |
| `kernel.dmesg_restrict` | 1 = unprivileged `dmesg` denied |
| `kernel.unprivileged_userfaultfd` | 0 = no userfaultfd for you; use FUSE instead |
| `kernel.unprivileged_bpf_disabled` | 1 = no eBPF verifier bugs |
| `kernel.modules_disabled` | 1 = no `insmod`, and `modprobe_path` still works |
| `kernel.perf_event_paranoid` | gates perf-based leaks |
| `vm.mmap_min_addr` | blocks NULL-page mapping (kills old null-deref exploits) |

## Attack

The decision procedure:

1. `cat /proc/cpuinfo | grep -o -E 'smep|smap'` and check the boot `cmdline`.
2. **No SMEP** -> ret2usr. Cheapest exploit; see `kernel-ret2usr-creds`.
3. **SMEP, no SMAP** -> kernel ROP with the chain in a user page (the kernel can still
   *read* it after a stack pivot to a user address... actually a pivot to a user stack
   requires reading it, so you still need SMAP off). Fake structures in userland are
   fine.
4. **SMEP + SMAP** -> everything the kernel reads must be kernel memory. Use
   `msg_msg`/`setxattr` sprays, or pivot onto a kernel heap object.
5. **+ KPTI** -> finish with `swapgs_restore_regs_and_return_to_usermode`.
6. **+ kCFI** -> avoid indirect calls entirely; use return-oriented chains or go
   data-only.
7. **Always consider `modprobe_path` first.** It needs one arbitrary write and defeats
   SMEP, SMAP, KPTI and kCFI simultaneously, because no code pointer is touched and no
   return to user space is needed.

## Heap state

```text
what each mitigation blocks

  user page (0x0000...)                kernel (0xffffffff81......)
  +-------------------+                +--------------------------+
  | your shellcode    |<--- SMEP ---X  | corrupted func pointer   |
  | your fake struct  |<--- SMAP ---X  | kernel reads a pointer   |
  | your ROP chain    |<--- SMAP ---X  | pivoted kernel stack     |
  +-------------------+                +--------------------------+

  KPTI: while in user mode the page tables map only the trampoline
  +-------------------+                +--------------------------+
  | user pages        |                | entry trampoline ONLY    |
  +-------------------+                | (rest of kernel unmapped)|
                                       +--------------------------+
   a bare `iretq` from your ROP chain -> #PF -> #DF -> triple fault

  KASLR: _text = 0xffffffff81000000 + (slide & ~0x1fffff)
         every symbol shifts by the same slide
         => one leaked kernel pointer defeats it

  kCFI: call *%rax  ->  cmp -4(%rax), $TYPE_HASH ; jne __cfi_slowpath
        pointing rax at "pop rdi; ret" fails the compare

  What survives ALL of them:
    *(char*)modprobe_path = "/tmp/x"    <- a plain data write
```

## Exploit

```c
/* mitigations.c - detect every mitigation from inside the guest.
 * Build: gcc -static -O2 -o mitigations mitigations.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    char line[8192];
    int found = 0;

    if (!f)
        return -1;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, needle)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static long read_long(const char *path)
{
    FILE *f = fopen(path, "r");
    long v = -1;

    if (!f)
        return -1;
    if (fscanf(f, "%ld", &v) != 1)
        v = -1;
    fclose(f);
    return v;
}

static void print_cmdline(void)
{
    int fd = open("/proc/cmdline", O_RDONLY);
    char buf[1024];
    ssize_t n;

    if (fd < 0)
        return;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return;
    buf[n] = 0;
    printf("[*] cmdline: %s", buf);
}

static unsigned long first_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    unsigned long addr = 0;

    if (!f)
        return 0;
    if (fscanf(f, "%lx", &addr) != 1)
        addr = 0;
    fclose(f);
    return addr;
}

static void verdict(const char *name, int on, const char *forces)
{
    printf("[%c] %-6s %-3s  -> %s\n", on > 0 ? '!' : '+', name,
           on > 0 ? "ON" : (on == 0 ? "off" : "?"), forces);
}

int main(void)
{
    int smep, smap, kpti, kaslr, cfi;
    unsigned long ks;

    print_cmdline();

    smep = file_contains("/proc/cpuinfo", " smep");
    smap = file_contains("/proc/cpuinfo", " smap");
    kpti = file_contains("/proc/cpuinfo", " pti");
    if (kpti <= 0)
        kpti = file_contains("/sys/devices/system/cpu/vulnerabilities/meltdown",
                             "PTI");
    kaslr = !file_contains("/proc/cmdline", "nokaslr");
    cfi = file_contains("/proc/cmdline", "cfi=");

    verdict("SMEP", smep, "no ret2usr: build a kernel ROP chain or go data-only");
    verdict("SMAP", smap, "no userland fake structs: spray msg_msg / setxattr");
    verdict("KPTI", kpti, "return via swapgs_restore_regs_and_return_to_usermode");
    verdict("KASLR", kaslr, "leak a kernel text pointer before using any address");
    verdict("kCFI", cfi, "no indirect calls to gadgets: use ret-chains or data-only");

    printf("[*] kptr_restrict    = %ld\n", read_long("/proc/sys/kernel/kptr_restrict"));
    printf("[*] dmesg_restrict   = %ld\n", read_long("/proc/sys/kernel/dmesg_restrict"));
    printf("[*] unpriv_userfaultfd = %ld\n",
           read_long("/proc/sys/vm/unprivileged_userfaultfd"));
    printf("[*] unpriv_bpf_disabled = %ld\n",
           read_long("/proc/sys/kernel/unprivileged_bpf_disabled"));
    printf("[*] mmap_min_addr    = %ld\n", read_long("/proc/sys/vm/mmap_min_addr"));

    ks = first_kallsyms();
    if (ks)
        printf("[+] /proc/kallsyms readable, first symbol at %#lx\n", ks);
    else
        printf("[!] /proc/kallsyms is zeroed or unreadable - you need a leak\n");

    puts("");
    puts("[*] reminder: modprobe_path beats SMEP + SMAP + KPTI + kCFI at once,");
    puts("    and needs nothing but a single arbitrary write.");
    return 0;
}
```

```bash
#!/bin/sh
# probe.sh - the same checks from the shell, for when you only have busybox.

# CPU features the kernel enabled
grep -o -E ' (smep|smap|pti)' /proc/cpuinfo | sort -u

# boot parameters: nokaslr / nopti / pti=on / cfi=
cat /proc/cmdline

# is /proc/kallsyms useful to us?
head -3 /proc/kallsyms

# the sysctls that gate the usual primitives
for f in kernel/kptr_restrict kernel/dmesg_restrict \
         kernel/unprivileged_bpf_disabled vm/unprivileged_userfaultfd \
         vm/mmap_min_addr kernel/modules_disabled; do
    printf '%-38s %s\n' "$f" "$(cat /proc/sys/$f 2>/dev/null || echo n/a)"
done

# Meltdown/Spectre mitigation status tells you about KPTI
cat /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null
```

## Variants & pitfalls

- **`+smep` in `-cpu` is necessary but not sufficient**: the kernel must also have
  `CONFIG_X86_SMAP`/SMEP support and not be booted with `nosmep`/`nosmap`.
- **QEMU's `-cpu qemu64` has neither** SMEP nor SMAP. Many "hard" challenges simply
  add `+smep,+smap` to an otherwise easy binary.
- **KASLR's 2 MB granularity** means the low 21 bits of every kernel symbol are
  constant. If you leak *any* kernel pointer you get the slide for free.
- **FG-KASLR** breaks `leaked_symbol - offset` arithmetic for functions but not for
  data symbols (`modprobe_path`, `core_pattern`), which is another reason data-only
  attacks are king.
- **The physmap defeats SMAP in spirit**: user pages are still mapped at
  `0xffff888000000000 + phys`. With 128 MB of guest RAM and a big spray you can guess
  a physmap address reliably.
- **`native_write_cr4` pinning** (4.15+) means the old "turn SMEP off" trick prints
  `WARNING: CPU: 0 PID: ... attempt to change unpinned cr4 bits` and does nothing.
- **kCFI is rare in CTF** but increasingly present in kernelCTF-style challenges.
- **Check `modules_disabled`**: even with it set, `modprobe_path` works, because the
  kernel still *execs* the path on `request_module`.

## Debugging

```text
pwndbg> p/x $cr4                  # bit 20 SMEP (0x100000), bit 21 SMAP (0x200000)
pwndbg> p/x $cr3                  # KPTI: the low bit flips between the two tables
pwndbg> p &_text
pwndbg> p/x (long)&_text - 0xffffffff81000000      # the KASLR slide
pwndbg> p &commit_creds
pwndbg> p &modprobe_path
pwndbg> x/s &modprobe_path
pwndbg> info symbol <leaked_pointer>
pwndbg> b swapgs_restore_regs_and_return_to_usermode
```

```bash
# Locally, strip the mitigations one at a time while developing.
# -cpu qemu64            : no SMEP, no SMAP
# -append "... nokaslr nopti"
qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz \
  -append "console=ttyS0 nokaslr nopti quiet" -cpu qemu64 -nographic -no-reboot -s
```

## Tools

- `qemu-system-x86_64` (toggle `+smep,+smap`).
- `gdb` + `pwndbg`/`gef` for `$cr4` and symbol rebasing.
- `extract-vmlinux` / `vmlinux-to-elf` for the symbol table.
- `ROPgadget` / `ropr` against `vmlinux` once you know what you need.

## References

- Linux kernel `Documentation/admin-guide/kernel-parameters.txt`.
- `arch/x86/kernel/cpu/common.c` (CR4 pinning), `arch/x86/entry/entry_64.S`
  (the KPTI trampoline).
