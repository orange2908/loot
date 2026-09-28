---
title: "angr Solver Template - stdin, argv, call_state and hooks"
category: rev
subcategory: angr
type: script
tags: [angr, claripy, symbolic-execution, concolic, simprocedure, hook, simfilestream, call-state, entry-state, veritesting, loopseer, unicorn, z3, crackme, keygen, flag-checker, python, emulation, path-explosion]
summary: "One --mode driven angr script covering the four crackme shapes (stdin, argv, function call, hooked helper) plus the state-option tuning that makes it finish."
tools: [angr, claripy, python, ipython]
related: [angr-symbolic-execution, z3-constraint-solving, angr-z3-cheatsheet, z3-flagsolver-template, unicorn-emulate-function, crackme-patterns, triage-unknown-binary]
---

## What this is

Four out of five angr CTF solves are one of four shapes. This is the script you
copy, plus the knobs you reach for when it does not terminate. Install with
`pip install angr` (pulls claripy, pyvex, cle, archinfo, unicorn, z3-solver).

| Shape | Input reaches the program via | Constructor |
|---|---|---|
| (a) stdin flag check | `scanf` / `fgets` / `read(0, ...)` | `full_init_state(stdin=SimFileStream(...))` |
| (b) argv | `./chal FLAG{...}` | `entry_state(args=[path, flag_bv])` |
| (c) function level | you found `int check(char *buf, int len)` | `call_state(addr, buf_ptr, length)` |
| (d) hooked | there is one expensive/unmodellable helper | `SimProcedure` + `proj.hook*` |

## Usage

```bash
# (a) stdin, 32 symbolic bytes, success at 0x401337, failure at 0x401350
python3 angr_solve.py ./chal --mode stdin --len 32 --find 0x401337 --avoid 0x401350

# (a') no known address - decide on the stdout text instead
python3 angr_solve.py ./chal --mode stdin --len 32 --find-str Correct

# (b) argv on a PIE binary - --find/--avoid are file offsets, rebased for you
python3 angr_solve.py ./chal --mode argv --len 24 --find 0x1337 --avoid 0x1350 --pie

# (c) call check(buf, 32) at 0x401200, want return value == 1
python3 angr_solve.py ./chal --mode func --func 0x401200 --len 32 --want-ret 1

# (d) as (a) but hook the sleep()/srand() helper at 0x401100 out of the way
python3 angr_solve.py ./chal --mode hook --len 32 --find 0x401337 --hook 0x401100
```

## The template

```python
#!/usr/bin/env python3
"""angr solver template - four challenge shapes behind one --mode switch.

Every mode ends the same way: constrain the symbolic input to printable bytes,
explore to `find` while pruning `avoid`, then eval the input BVS in the found
state. The differences are only in HOW the symbolic bytes enter the program.
"""
import argparse
import logging
import sys

import angr
import claripy

# angr is chatty; keep WARNING so you still see "no addresses found" complaints.
logging.getLogger("angr").setLevel(logging.WARNING)
logging.getLogger("cle").setLevel(logging.ERROR)

# Scratch memory used by --mode func: pages that are not part of any segment.
SCRATCH = 0x0F000000
STACK_SCRATCH = 0x0F001000

# ZERO_FILL_* stops angr inventing a fresh symbol for every uninitialised byte
# (a huge source of fake state divergence) and silences the matching warnings.
# LAZY_SOLVES defers SAT checks to the end of a block: usually faster, but it
# lets infeasible states live longer - re-check satisfiable() before eval.
OPTS = {
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    angr.options.LAZY_SOLVES,
} | angr.options.unicorn                    # unicorn: native concrete execution


def make_project(path, pin_base=None):
    """auto_load_libs=False is the single biggest speed win: without it angr
    symbolically executes the real libc and printf alone explodes the state
    space. With it, unresolved imports get a SimProcedure stub. pin_base forces
    the load address so your IDA/Ghidra addresses work as-is."""
    main_opts = {"base_addr": pin_base} if pin_base is not None else {}
    return angr.Project(path, auto_load_libs=False, main_opts=main_opts)


def base_of(proj, pie):
    """PIE binaries are loaded at 0x400000/0x555555554000 depending on version.
    Ghidra/IDA show file offsets, so rebase: real = min_addr + offset."""
    return proj.loader.main_object.min_addr if pie else 0


def flag_bytes(length):
    """One 8-bit BVS per character. Per-byte symbols (not one big BVS) make the
    printable constraints readable and let you print a partial solution."""
    return [claripy.BVS("b_%02d" % i, 8) for i in range(length)]


def constrain_printable(state, chars, charset=None):
    """Narrow the search space. Nearly every flag is printable ASCII; if you
    know the alphabet (hex, base64) pass it and the solve gets much faster."""
    for c in chars:
        if charset:
            state.solver.add(claripy.Or(*[c == ord(x) for x in charset]))
        else:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7E)


def build_stdin_state(proj, chars):
    """(a) Symbolic stdin. SimFileStream + has_end=False means reads never hit
    EOF, so a program looping on getchar() will not fork on 'is it EOF yet'.
    Append a newline so fgets/scanf terminate exactly where we want."""
    flag = claripy.Concat(*chars, claripy.BVV(b"\n"))
    stdin = angr.SimFileStream(name="stdin", content=flag, has_end=False)
    st = proj.factory.full_init_state(stdin=stdin, add_options=OPTS)
    constrain_printable(st, chars)
    return st


def build_argv_state(proj, chars, binpath):
    """(b) Symbolic argv[1]. entry_state skips libc init (faster than
    full_init_state) and is fine unless the binary needs constructors."""
    st = proj.factory.entry_state(args=[binpath, claripy.Concat(*chars)],
                                  add_options=OPTS)
    constrain_printable(st, chars)
    return st


def build_call_state(proj, chars, func_addr, length):
    """(c) Skip main entirely and call one function. Write the symbolic buffer
    into scratch memory yourself; call_state's positional args go into the
    target arch's argument registers (RDI/RSI on amd64, x0/x1 on aarch64)."""
    st = proj.factory.call_state(
        func_addr,
        SCRATCH,               # -> rdi : char *buf
        length,                # -> rsi : int len
        add_options=OPTS,
        stack_base=STACK_SCRATCH + 0x9000,
    )
    st.memory.store(SCRATCH, claripy.Concat(*chars))
    st.memory.store(SCRATCH + length, claripy.BVV(0, 8))   # NUL terminate
    constrain_printable(st, chars)
    return st


class ExpensiveStub(angr.SimProcedure):
    """(d) Replace a function angr cannot or should not execute: a sleep, a
    ptrace anti-debug check, an srand/rand pair, a 10^6-round hash. run()'s
    parameters map to the ABI argument registers; self.state is the live
    SimState; return a concrete value or a fresh BVS."""

    def run(self, arg0=None, arg1=None):   # noqa: D401 - angr calls this
        return claripy.BVV(0, self.state.arch.bits)


def install_hooks(proj, hook_addr):
    """Three hooking flavours, all useful:
    1. proj.hook_symbol - by name, works for imports and for exported locals.
    2. proj.hook(addr, SimProcedure()) - replaces the whole function at addr.
    3. @proj.hook(addr, length=N) - inline patch: run python, then continue at
       addr+N. Use length=0 to run python and then execute the real instruction.
    """
    if proj.loader.find_symbol("rand") is not None:
        proj.hook_symbol("rand", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
    if hook_addr is not None:
        proj.hook(hook_addr, ExpensiveStub())


def run(proj, state, find, avoid, find_str, num_find):
    """explore() with a stash discipline. Dropping the avoid stash keeps memory
    flat on long runs - angr otherwise keeps every dead state alive."""
    simgr = proj.factory.simulation_manager(state)
    # Veritesting merges states at post-dominators: excellent for flat
    # byte-by-byte comparison loops, harmful when the loop body is tiny.
    simgr.use_technique(angr.exploration_techniques.Veritesting())
    # Cap any loop at 40 iterations; bail out before the OOM killer does.
    simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=40))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024))

    if find_str is not None:
        want = find_str.encode()

        def good(st):
            return want in st.posix.dumps(1)

        def bad(st):
            return b"Wrong" in st.posix.dumps(1) or b"Nope" in st.posix.dumps(1)

        simgr.explore(find=good, avoid=bad, num_find=num_find)
    else:
        simgr.explore(find=find, avoid=avoid, num_find=num_find)
        simgr.drop(stash="avoid")

    return simgr


def report(simgr, chars, mode, want_ret, length):
    if not simgr.found:
        print("[-] no state reached the target. stashes: %r" % (simgr.stashes,))
        print("    try: --find-str, a bigger --len, DFS, or drop Veritesting")
        return 1
    for i, found in enumerate(simgr.found):
        if mode == "func" and want_ret is not None:
            found.solver.add(found.regs.rax == want_ret)   # rax on amd64
            if not found.satisfiable():
                print("[-] found state cannot return %d" % want_ret)
                continue
        print("[+] solution %d: %r" % (i, bytes(found.solver.eval(c, cast_to=int)
                                                for c in chars)))
        if mode == "stdin":
            print("    stdin : %r" % found.posix.dumps(0)[:length + 1])
        print("    stdout: %r" % found.posix.dumps(1))
    return 0


def main(argv=None):
    hx = lambda x: int(x, 0)              # noqa: E731 - accepts hex or decimal
    ap = argparse.ArgumentParser(description="angr solver template")
    ap.add_argument("binary", nargs="?", default="./chal")
    ap.add_argument("--mode", choices=["stdin", "argv", "func", "hook"], default="stdin")
    ap.add_argument("--len", dest="length", type=int, default=32)
    ap.add_argument("--find", type=hx, default=None)
    ap.add_argument("--avoid", type=hx, default=None)
    ap.add_argument("--find-str", default=None, help="match stdout, not an address")
    ap.add_argument("--func", type=hx, default=None)
    ap.add_argument("--hook", type=hx, default=None)
    ap.add_argument("--want-ret", type=hx, default=None)
    ap.add_argument("--num-find", type=int, default=1, help=">1 proves uniqueness")
    ap.add_argument("--pie", action="store_true", help="--find/--avoid are offsets")
    args = ap.parse_args(argv)

    proj = make_project(args.binary)
    base = base_of(proj, args.pie)
    find = args.find + base if args.find is not None else None
    avoid = args.avoid + base if args.avoid is not None else None
    chars = flag_bytes(args.length)

    if args.mode == "argv":
        state = build_argv_state(proj, chars, args.binary)
    elif args.mode == "func":
        if args.func is None:
            ap.error("--mode func needs --func ADDR")
        state = build_call_state(proj, chars, args.func + base, args.length)
    else:
        if args.mode == "hook":
            install_hooks(proj, args.hook + base if args.hook is not None else None)
        state = build_stdin_state(proj, chars)

    simgr = run(proj, state, find, avoid, args.find_str, args.num_find)
    return report(simgr, chars, args.mode, args.want_ret, args.length)


if __name__ == "__main__":
    sys.exit(main())
```

## Variant snippets

The stdout predicate on its own - use it when there is no clean success address
(common when `puts("Correct")` is inlined into a switch):

```python
import angr

proj = angr.Project("./chal", auto_load_libs=False)
simgr = proj.factory.simulation_manager(proj.factory.full_init_state())
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),
    avoid=lambda s: b"Wrong" in s.posix.dumps(1),
)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

Reading a *result buffer* rather than a return value in `--mode func` (the
function writes the transformed flag to `out`):

```python
import angr
import claripy

proj = angr.Project("./chal", auto_load_libs=False)
IN, OUT, N = 0x0F000000, 0x0F002000, 32
chars = [claripy.BVS("b%d" % i, 8) for i in range(N)]

state = proj.factory.call_state(0x401200, IN, OUT, N)
state.memory.store(IN, claripy.Concat(*chars))
for c in chars:
    state.solver.add(c >= 0x20, c <= 0x7E)

simgr = proj.factory.simulation_manager(state)
simgr.run()                                   # run to the call_state sentinel
final = simgr.deadended[0]
out = final.memory.load(OUT, N)               # 32-byte BV, big-endian
final.solver.add(out == claripy.BVV(b"\x13\x37" * 16, N * 8))
print(bytes(final.solver.eval(c, cast_to=int) for c in chars))
```

A hand-written `SimProcedure` that actually models something, plus the inline
hook form:

```python
import angr
import claripy


class FakeStrlen(angr.SimProcedure):
    """Concrete length for a known-length symbolic buffer: kills the whole
    'string could be any length' fork tree."""

    def run(self, s, length=32):
        return claripy.BVV(length, self.state.arch.bits)


class CheckSum(angr.SimProcedure):
    """Model an opaque helper: read the buffer yourself, return a symbolic sum."""

    def run(self, buf, n):
        n_conc = self.state.solver.eval(n)
        total = claripy.BVV(0, 32)
        for i in range(n_conc):
            total = total + self.state.memory.load(buf + i, 1).zero_extend(24)
        return total


proj = angr.Project("./chal", auto_load_libs=False)
proj.hook_symbol("strlen", FakeStrlen())          # by name
proj.hook(0x401540, CheckSum())                   # whole function at addr


@proj.hook(0x4011a9, length=5)                    # inline: skip 5 bytes
def skip_ptrace(state):
    """Neutralise `call ptrace` - set the return register and fall through to
    0x4011a9 + 5. length=0 would run this and then the original instruction."""
    state.regs.rax = 0
```

## Tuning - the knobs, in the order you should try them

```python
import angr

# 1. Never load libc symbolically. Do this always, first.
proj = angr.Project("./chal", auto_load_libs=False)

# 2. PIE rebasing. Ghidra shows 0x101234; angr loads PIE at 0x400000.
#    Alternative: main_opts={"base_addr": 0x400000} to pin the load address.
base = proj.loader.main_object.min_addr
find_addr = base + 0x1234

# 3. State options, cheapest first (see OPTS in the template above).
state = proj.factory.entry_state(add_options=angr.options.unicorn | {
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,     # no fresh symbol per byte
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    angr.options.LAZY_SOLVES,                        # defer SAT checks
})

# 4. Exploration techniques. Pick, do not stack all of them blindly.
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.Veritesting())         # merges
simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=64))    # caps loops
simgr.use_technique(angr.exploration_techniques.DFS())                 # low memory
simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024))

# 5. Prune. Dead states still cost RAM.
simgr.explore(find=find_addr, avoid=[base + 0x1350, base + 0x1380], num_find=2)
simgr.drop(stash="avoid")
simgr.drop(stash="deadended")

# 6. num_find=2 proves uniqueness: if two distinct inputs reach the success
#    block, your constraint set is under-specified (usually a too-short --len).
print(len(simgr.found))
```

Rules of thumb:

- `auto_load_libs=False` is not optional - it is a 10x-100x difference.
- Symbolic length is the enemy. Fix the input length; pad with a newline.
- `unicorn` only helps when large stretches are concrete; pure-symbolic loops
  gain nothing and the engine thrashes in and out of native mode.
- `Veritesting` shines on `for (i=0;i<32;i++) if (buf[i]!=k[i]) ok=0;`, hurts on
  tight loops with a symbolic trip count.
- `LAZY_SOLVES` speeds exploration but a *found* state may be unsatisfiable.
- 5 minutes with a growing `active` stash means path explosion: stop, and hook
  the offending function instead. For RAM, `DFS()` plus `simgr.drop()`.

## When angr is the wrong tool

Reach for something else when:

- **The check is one arithmetic relation.** Read it out of the decompiler and
  write 15 lines of z3 (`z3-flagsolver-template`). angr's job is to *find* the
  constraints; if you already have them, skip it.
- **There is a per-byte early exit** (`if (buf[i] != f(i)) return 0;`). That is a
  256*N brute force with an instruction-count or emulation oracle - see
  `side-channel-instruction-counting` and `unicorn-emulate-function`.
- **Heavy crypto** (SHA-256, AES, a 10^6-round PBKDF): the SMT formula is
  hopeless. Hook it, or attack the maths.
- **A custom VM interpreter.** The dispatch loop explodes immediately. Lift the
  bytecode instead (`custom-vm-bytecode`).
- **Self-modifying / packed code.** cle loads the packed image and angr executes
  the wrong bytes. Unpack first (`packers-and-unpacking`).
- **Syscall-heavy or network code.** Write SimProcedures for everything, or
  emulate with qiling (`unicorn-qiling-emulation`).

Heuristic: angr is for *a few hundred symbolic bytes flowing through a few
thousand instructions*. Outside that box, pick another tool.

## References

- angr documentation and API reference - docs.angr.io
- angr examples repository - github.com/angr/angr-doc (`examples/` has one
  directory per solved CTF challenge; read `fauxware` first)
- angr_ctf exercise set - github.com/jakespringer/angr_ctf (graded levels that
  map almost 1:1 onto the four modes above)
