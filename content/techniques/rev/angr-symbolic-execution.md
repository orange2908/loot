---
title: "angr - Symbolic Execution for Keygens and Flag Checkers"
category: rev
subcategory: angr
type: technique
tags: [angr, symbolic-execution, claripy, z3, simulation-manager, simprocedure, unicorn, veritesting, loopseer, state-explosion, keygen, flag-checker, hooking, pie, bitvector, emulation, python]
difficulty: medium
summary: "Drive angr to find the input that reaches a 'Correct!' basic block: entry/blank/call states, explore(find=, avoid=), symbolic stdin/argv, hooks, and state-explosion control."
when_to_use:
  - "A crackme reads a flag/serial and prints one of two messages; you can find the win/lose addresses"
  - "The checking logic is a long chain of arithmetic on individual bytes and hand-reversing is slow"
  - "You need a keygen: solve for any input satisfying the constraints, not just one hardcoded flag"
  - "A small function computes a checksum and you want angr to invert it via call_state"
  - "NOT when the check loops thousands of times with data-dependent branching (use z3 on the decompiled math instead)"
tools: [angr, claripy, z3, ipython, ghidra]
related: [angr-template, z3-constraint-solving, angr-z3-cheatsheet, unicorn-qiling-emulation, custom-vm-bytecode, side-channel-instruction-counting]
---

## TL;DR

angr symbolically executes a binary: every input byte becomes a free variable, every branch
forks a state, and at the end you ask the SMT solver "what input reaches address X?".
It wins on flag checkers with shallow, straight-line, per-byte logic. It loses hard on loops
with data-dependent branching - there the number of states doubles every iteration and you
must either hook the loop away or drop angr and model the math in z3 directly.

Install: `pip install angr` (brings claripy, pyvex, cle, z3-solver). Use a venv, angr pins versions.

## Recognise it

- Binary prints exactly two outcomes: `Correct!` / `Wrong!`, `Access granted` / `Denied`.
- `strcmp`-free check: a `for` loop over the input doing `buf[i] ^ k` / `+ i` / rotates,
  then a single comparison at the end.
- Ghidra shows a chain of `if (x != const) goto fail;` - one block per byte. Perfect for angr.
- The input arrives via `scanf`/`fgets` on stdin, `argv[1]`, or a `read(0, buf, N)`.
- Input length is known and small (8-48 bytes). Longer is fine only if the logic is per-byte.

Counter-signal (angr is the wrong tool): a loop like
```c
for (i = 0; i < 32; i++) {
    if (buf[i] & 1) state = state * 0x1f + buf[i];   // data-dependent branch
    else            state = (state >> 3) ^ buf[i];
}
```
That is 2^32 paths. angr will eat all RAM. Model it in z3 (see `z3-constraint-solving`).

## Theory

angr lifts machine code to VEX IR, then interprets it over `claripy` bitvector ASTs
instead of concrete numbers. A `SimState` holds registers, memory, the file system, and a
set of path constraints. Executing a conditional jump on a symbolic condition produces two
successor states, each with the branch predicate added to its constraint set. A
`SimulationManager` (`simgr`) holds stashes of states: `active`, `found`, `avoid`,
`deadended`, `errored`, `unconstrained`.

`explore(find=A, avoid=B)` steps the `active` stash until a state's instruction pointer hits
`A` (moved to `found`) or `B` (moved to `avoid` and pruned). Then
`state.solver.eval(bv, cast_to=bytes)` asks z3 for a concrete assignment of the input
bitvector consistent with every constraint collected along that path.

Three ways to build the starting state:

| Constructor | Use when |
|---|---|
| `proj.factory.entry_state()` | Normal ELF, you want `main` reached through libc startup |
| `proj.factory.blank_state(addr=0x401337)` | Skip setup; jump straight into the middle of a function. Registers/memory are unconstrained (or zero-filled) unless you set them |
| `proj.factory.call_state(addr, a1, a2)` | Call one function like a Python function: sets up a fake return address and the ABI registers |

`auto_load_libs=False` is almost always right: it stops CLE from loading the real libc, so
angr substitutes its own fast `SimProcedure` for `printf`, `strlen`, `memcmp`, etc. With real
libc loaded, angr symbolically executes libc's SSE `strlen` and dies.

## Workflow

1. Triage first: `file ./chal && checksec --file=./chal && strings -n 6 ./chal | head -40`.
   Note PIE or not, and the success/failure strings.
2. Find the win address. In Ghidra: xref the `"Correct"` string, take the address of the
   `puts` call **or better** the basic block that dominates it. In radare2:
   `r2 -q -c 'aaa; /s Correct; axt @ hit0_0' ./chal`.
3. Non-PIE (`0x400000`/`0x8048000` base): use the addresses as-is. PIE (base `0x0`): angr
   maps the main object at `0x400000` by default, so `win = 0x400000 + ghidra_offset`, or
   compute `base = proj.loader.main_object.min_addr` and add the Ghidra offset minus
   Ghidra's own image base (usually `0x100000`).
4. Write the script: symbolic input, `simgr.explore(find=win, avoid=fail)`.
5. If it hangs: add `avoid` addresses for every `puts("Wrong")`, add
   `angr.options.LAZY_SOLVES`, then `unicorn`, then `Veritesting`, then hook the slow
   function with a `SimProcedure`.
6. If it still hangs, you are in state explosion. Stop. Reverse the loop by hand into z3.

Quick PIE base check:
```sh
# angr's mapped base for the main object; compare to Ghidra's image base
python3 -c "import angr,sys; p=angr.Project(sys.argv[1],auto_load_libs=False); print(hex(p.loader.main_object.min_addr))" ./chal
```

## Code

### 1. Full solver: symbolic stdin, explore by address

The most common shape. `SimFileStream` replaces stdin with a file whose content is a
symbolic bitvector, so `fgets`/`read`/`scanf` pull symbolic bytes.

```python
#!/usr/bin/env python3
"""angr solver: symbolic stdin, explore to a 'Correct' block.

Usage: python3 solve_stdin.py ./chal [win_addr] [fail_addr]
Addresses are hex. Defaults are for a non-PIE 0x400000-based binary.
"""
import sys

import angr
import claripy

FLAG_LEN = 32


def build_flag():
    """One 8-bit symbolic variable per flag byte -> easier to debug than one big BVS."""
    chars = [claripy.BVS(f"flag_{i}", 8) for i in range(FLAG_LEN)]
    return chars, claripy.Concat(*chars)


def constrain_printable(state, chars):
    """Restrict each byte to [a-zA-Z0-9_{}]. Massively prunes the search space."""
    for ch in chars:
        state.solver.add(
            claripy.Or(
                claripy.And(ch >= ord("a"), ch <= ord("z")),
                claripy.And(ch >= ord("A"), ch <= ord("Z")),
                claripy.And(ch >= ord("0"), ch <= ord("9")),
                ch == ord("_"),
                ch == ord("{"),
                ch == ord("}"),
            )
        )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    win = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x401337
    fail = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x401360

    # auto_load_libs=False -> angr stubs libc with fast SimProcedures instead of
    # symbolically executing real SSE strlen/printf.
    proj = angr.Project(path, auto_load_libs=False)

    chars, flag = build_flag()

    # SimFileStream: a stream-like file so read()/fgets() consume bytes in order.
    # has_end=False means "never EOF", avoiding spurious short-read paths.
    stdin = angr.SimFileStream(name="stdin", content=flag, has_end=False)

    state = proj.factory.entry_state(
        stdin=stdin,
        add_options={
            # Unconstrained reads return 0 instead of a fresh symbol -> far fewer states.
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            # Defer solver calls until a state is actually inspected.
            angr.options.LAZY_SOLVES,
        },
    )
    constrain_printable(state, chars)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=win, avoid=fail)

    if not simgr.found:
        print("[-] no path to win; stashes:", {k: len(v) for k, v in simgr.stashes.items()})
        return 1

    found = simgr.found[0]
    # cast_to=bytes turns the 256-bit AST into a b'...' literal.
    solution = found.solver.eval(flag, cast_to=bytes)
    print("[+] flag:", solution.decode(errors="replace"))
    print("[+] stdout:", found.posix.dumps(1).decode(errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 2. No known win address: explore on stdout content

When the binary is stripped/PIE and finding the win block is annoying, match on output
instead. The lambda runs on every stepped state, so keep it cheap.

```python
#!/usr/bin/env python3
"""angr solver keyed on program output rather than an address.

Usage: python3 solve_stdout.py ./chal
"""
import sys

import angr
import claripy

FLAG_LEN = 24
GOOD = b"Correct"
BAD = b"Wrong"


def is_good(state):
    return GOOD in state.posix.dumps(1)


def is_bad(state):
    return BAD in state.posix.dumps(1)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    proj = angr.Project(path, auto_load_libs=False)

    flag = claripy.BVS("flag", FLAG_LEN * 8)
    stdin = angr.SimFileStream(name="stdin", content=flag, has_end=False)
    state = proj.factory.entry_state(
        stdin=stdin,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Printable-ASCII constraint on every byte via Extract on the big BVS.
    for i in range(FLAG_LEN):
        byte = flag.get_byte(i)
        state.solver.add(byte >= 0x20, byte <= 0x7E)

    simgr = proj.factory.simulation_manager(state)
    # LoopSeer bounds each loop to 60 iterations so a length loop cannot run forever.
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=None, bound=60))
    simgr.explore(find=is_good, avoid=is_bad)

    if not simgr.found:
        print("[-] not found")
        return 1

    st = simgr.found[0]
    print("[+] flag:", st.solver.eval(flag, cast_to=bytes).decode(errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 3. call_state + hooking: invert one function, skip the slow one

Use when the interesting logic is a single `int check(char *buf, int len)` and the binary
also calls something expensive (sha256, a sleep loop, a custom strlen). `hook_symbol`
replaces a named import; `project.hook(addr, ...)` replaces a raw address.

```python
#!/usr/bin/env python3
"""angr: call one function directly, hook away the expensive helper.

Usage: python3 solve_callstate.py ./chal 0x401200 32
  argv[2] = address of check(char *buf, size_t len)
  argv[3] = buffer length
"""
import sys

import angr
import claripy


class FakeStrlen(angr.SimProcedure):
    """Replace strlen with a constant: the caller already knows the length."""

    def run(self, s):  # noqa: ARG002 - angr passes the pointer arg
        return claripy.BVV(FLAG_LEN, self.state.arch.bits)


class Sha256Stub(angr.SimProcedure):
    """Stub out a hash we do not want to symbolically execute; returns 0 (success)."""

    def run(self, data, length, out):
        # Write 32 concrete zero bytes to the output buffer so downstream code is sane.
        self.state.memory.store(out, b"\x00" * 32)
        return claripy.BVV(0, self.state.arch.bits)


FLAG_LEN = 32


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    check_addr = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x401200
    length = int(sys.argv[3]) if len(sys.argv) > 3 else FLAG_LEN

    proj = angr.Project(path, auto_load_libs=False)

    # Replace imports by name (works through the PLT).
    if "strlen" in proj.loader.main_object.imports:
        proj.hook_symbol("strlen", FakeStrlen())
    if "SHA256" in proj.loader.main_object.imports:
        proj.hook_symbol("SHA256", Sha256Stub())

    # Skip a 5-instruction anti-debug stub at a raw address.
    # length= tells angr how many bytes of original code to skip over.
    @proj.hook(0x4011A0, length=5)
    def skip_ptrace(state):
        state.regs.rax = 0

    # Put the symbolic buffer somewhere writable and pass its pointer.
    buf_addr = 0x500000
    flag = claripy.BVS("flag", length * 8)

    state = proj.factory.call_state(
        check_addr,
        buf_addr,
        length,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.memory.store(buf_addr, flag)
    for i in range(length):
        b = flag.get_byte(i)
        state.solver.add(b >= 0x21, b <= 0x7E)

    simgr = proj.factory.simulation_manager(state)
    # Run to the fake return address angr installed; deadended states are returns.
    simgr.run()

    for st in simgr.deadended:
        # call_state returns land in rax on x86-64 SysV.
        if st.solver.satisfiable(extra_constraints=[st.regs.rax == 1]):
            st.solver.add(st.regs.rax == 1)
            print("[+] flag:", st.solver.eval(flag, cast_to=bytes).decode(errors="replace"))
            return 0
    print("[-] no returning state with rax == 1")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 4. Symbolic argv

```python
#!/usr/bin/env python3
"""Solve ./chal <serial> where the serial is argv[1]."""
import sys

import angr
import claripy

ARG_LEN = 16


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    win = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x4012F0

    proj = angr.Project(path, auto_load_libs=False)
    arg = claripy.BVS("arg", ARG_LEN * 8)

    # argv[0] must be the concrete program name; argv[1] is our symbol.
    state = proj.factory.entry_state(
        args=[path, arg],
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )
    for i in range(ARG_LEN):
        c = arg.get_byte(i)
        state.solver.add(c >= 0x30, c <= 0x7A)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=win)
    if simgr.found:
        print("[+]", simgr.found[0].solver.eval(arg, cast_to=bytes))
        return 0
    print("[-] unsat")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 5. Taming state explosion

Apply in this order; each costs something.

```python
#!/usr/bin/env python3
"""Exploration-technique menu for a heavy angr run. Import and pick what you need."""
import angr


def tune(proj, simgr, mode="fast"):
    """mode: fast | dfs | veritesting | spill"""
    if mode == "fast":
        # unicorn: run concrete chunks natively through the Unicorn engine.
        # Only helps when much of the path is concrete (setup code, memcpy).
        for st in simgr.active:
            st.options.update(angr.options.unicorn)
            st.options.add(angr.options.LAZY_SOLVES)
    elif mode == "dfs":
        # Depth-first: keeps exactly one active state -> flat memory usage.
        # Good when ANY solution is fine and the tree is deep but narrow.
        simgr.use_technique(angr.exploration_techniques.DFS())
    elif mode == "veritesting":
        # Static symbolic execution merges states that reconverge after an if/else.
        # Turns 2^n per-byte branches into one merged state. Huge win on byte checkers.
        simgr.use_technique(angr.exploration_techniques.Veritesting())
    elif mode == "spill":
        # Page out surplus states to disk (ana storage) instead of OOM-ing.
        simgr.use_technique(angr.exploration_techniques.Spiller())

    # Always worth it: bound loops, and bail out before the OOM killer does.
    simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=128))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
    return simgr


def step_and_prune(simgr, win, fail_addrs, max_steps=4000):
    """Manual loop: drop the avoid stash every step so it never accumulates."""
    for _ in range(max_steps):
        if not simgr.active:
            break
        simgr.step()
        simgr.move(from_stash="active", to_stash="avoid",
                   filter_func=lambda s: s.addr in fail_addrs)
        simgr.move(from_stash="active", to_stash="found",
                   filter_func=lambda s: s.addr == win)
        # Free the memory held by pruned states.
        simgr.drop(stash="avoid")
        # Also drop anything that errored (unmapped reads from bad hooks).
        simgr.drop(stash="errored")
        if simgr.found:
            return simgr.found[0]
    return None


if __name__ == "__main__":
    print("import this module from your solver; see tune() and step_and_prune()")
```

## Variants & pitfalls

- **PIE addresses.** Ghidra shows `0x00101337` for a PIE binary (image base `0x100000`).
  angr maps at `0x400000`. So `angr_addr = 0x400000 + (ghidra_addr - 0x100000)`. Always
  print `hex(proj.loader.main_object.min_addr)` before trusting an address. Prefer
  `proj.loader.find_symbol("check").rebased_addr` when symbols exist.
- **`auto_load_libs=True` is a trap.** It loads real libc; `printf` becomes thousands of
  symbolic blocks. Only enable it when you specifically need real libc behaviour.
- **Unconstrained stdin length.** Without `has_end=False`, angr forks a state for every
  possible read length. Fix it with `SimFileStream(..., has_end=False)` or by passing a
  fixed-size `content` plus `state.posix.stdin.size` constraints.
- **Missing null terminator.** If the code calls `strlen(buf)`, add a concrete `\n` or
  `\x00` after the symbolic bytes, or angr explores every possible terminator position.
- **`find=` matching too early.** If the win address is inside a loop or is the `puts` PLT
  stub, you get a bogus hit. Use the address of the basic block right before the success
  `puts`, i.e. the unique dominator.
- **`LAZY_SOLVES` gives unreachable "found" states.** It defers satisfiability checks, so a
  found state may be unsat. Always verify: `assert found.solver.satisfiable()` before eval,
  or re-run the found path without the option.
- **`eval` returns one of many solutions.** For a keygen, enumerate with
  `found.solver.eval_upto(flag, 10, cast_to=bytes)`. For a unique flag, check uniqueness
  by adding `flag != first_solution` and re-solving.
- **Non-printable garbage in the answer.** You forgot the printable constraint. Bytes that
  are never read by the program are free and come back as `\x00`.
- **When angr is the wrong tool.** Loops over >16-32 bytes with data-dependent branching,
  crypto primitives (AES/SHA/RC4 with symbolic key), VM interpreters with a symbolic
  program counter, and anything with `rand()`/time. In all of those, extract the math from
  the decompiler and hand it to z3 (`z3-constraint-solving`), or emulate concretely with
  Unicorn (`unicorn-qiling-emulation`) and brute-force byte-by-byte using an instruction
  count side channel (`side-channel-instruction-counting`).
- **Hook length matters.** `proj.hook(addr, fn, length=N)` resumes execution at `addr+N`.
  Get `N` wrong and you resume mid-instruction. `length=0` (default) means the hook
  replaces a function call and must set the return itself.
- **`errored` stash is silent.** Inspect it: `simgr.errored[0].error` and
  `simgr.errored[0].state.addr` usually point at an unmapped memory access caused by a
  `blank_state` with no stack set up. Fix with `state.regs.rsp = 0x7fff0000` and mapping
  that region.
- **Speed sanity check.** A good angr run on a 32-byte per-byte checker finishes in
  10-120 seconds. If you are past 10 minutes with no `found`, the approach is wrong;
  change tools rather than waiting.

## Tools

- `angr` - the engine. `pip install angr` into a venv.
- `claripy` - the AST/solver frontend (`BVS`, `BVV`, `Concat`, `Extract`, `Or`, `And`).
- `cle` - the loader; `proj.loader.main_object`, `.min_addr`, `.imports`, `find_symbol`.
- `angrop` / `angr-management` - ROP chains and a GUI, occasionally useful.
- `ipython` - run the solver interactively so you keep `simgr` alive after a failure.
- Ghidra / radare2 - to get the win and fail addresses in the first place.

## References

- angr official documentation and examples repository (angr.io, github.com/angr/angr-doc) -
  the `examples/` directory contains one solver per classic CTF crackme.
- angr API docs for `SimulationManager`, `ExplorationTechnique`, `SimProcedure`.
- See also: `z3-constraint-solving`, `unicorn-qiling-emulation`, `angr-z3-cheatsheet`,
  `angr-template`.
