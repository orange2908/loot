---
title: "Tool - angr"
category: rev
subcategory: symbolic-execution
type: tool
tags: [angr, symbolic-execution, concolic, claripy, z3, solver, rev, crackme, path-explosion, simprocedure, hooks, state-explosion, binary-analysis, automated-solving]
summary: "Python binary analysis framework with symbolic execution: give it a 'win' address and it solves for the input that reaches it."
related: [rev-triage, z3, ghidra, radare2]
---

## What it is

`angr` loads a binary, lifts it to an intermediate representation, and executes it with **symbolic** inputs - values that are constraints rather than concrete bytes. When execution reaches a state you asked for, the constraint solver (z3, via `claripy`) produces an input that gets there. For CTF, that means: point it at the "Correct!" branch and it hands you the flag.

It is the right tool for a branch maze with a bounded input. It is the wrong tool for anything involving hashing, long loops, or large unknown input lengths.

## Install

```sh
# angr pulls in a lot; always use an isolated environment
pipx install angr
# or
python3 -m venv ~/.venvs/angr && ~/.venvs/angr/bin/pip install angr
# verify
python3 -c "import angr; print(angr.__version__)"
```

## The invocations that matter

```python
#!/usr/bin/env python3
"""angr solving patterns. Pick the one matching how the binary reads input."""
import angr
import claripy
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "./chal"

# 1. the loader; auto_load_libs=False is almost always what you want
proj = angr.Project(BIN, auto_load_libs=False)
print(hex(proj.entry), proj.arch.name, proj.loader.main_object.pic)

# 2. input on stdin, fixed length
FLAG_LEN = 32
flag = claripy.BVS("flag", FLAG_LEN * 8)
state = proj.factory.full_init_state(args=[BIN], stdin=flag)

# 3. constrain to printable - without this the solver wanders for hours
for i in range(FLAG_LEN):
    b = flag.get_byte(i)
    state.solver.add(claripy.Or(b == 0x0a, claripy.And(b >= 0x20, b <= 0x7e)))

# 4. explore by output string (robust, no addresses needed)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
              avoid=lambda s: b"Wrong" in s.posix.dumps(1))

# 5. explore by address (faster; get the addresses from Ghidra/r2)
#    with PIE, add proj.loader.main_object.mapped_base to the file offsets
# simgr.explore(find=0x401337, avoid=[0x401300, 0x401310])

# 6. read the answer
if simgr.found:
    s = simgr.found[0]
    print(s.solver.eval(flag, cast_to=bytes))
    print(s.posix.dumps(0))      # everything that was fed to stdin

# 7. input as argv instead of stdin
argv1 = claripy.BVS("argv1", 20 * 8)
state = proj.factory.full_init_state(args=[BIN, argv1])

# 8. hook an expensive function (a hash, a sleep, a printf) to skip it
@proj.hook(0x401500, length=5)
def skip_it(state):
    state.regs.eax = 0

# 9. replace a library function wholesale
proj.hook_symbol("strlen", angr.SIM_PROCEDURES["libc"]["strlen"]())

# 10. start mid-function with a blank state (when full_init_state is too slow)
state = proj.factory.blank_state(addr=0x401200)
state.memory.store(0x404040, flag)          # place the symbolic buffer where the code expects it
```

Speed options that matter:
```python
state = proj.factory.full_init_state(
    args=[BIN], stdin=flag,
    add_options=angr.options.unicorn | {
        angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    },
)
```
Managing state explosion:
```python
simgr.use_technique(angr.exploration_techniques.DFS())          # depth-first, low memory
simgr.use_technique(angr.exploration_techniques.Veritesting())  # merges paths
simgr.use_technique(angr.exploration_techniques.LengthLimiter(1000))
simgr.explore(find=..., num_find=1)
print(simgr)   # watch the active/deadended/found counts
```

Automatic exploit generation (for simple stack overflows):
```python
p = angr.Project("./chal")
sm = p.factory.simgr(p.factory.full_init_state(), save_unconstrained=True)
sm.use_technique(angr.exploration_techniques.Tracer())  # or just run until unconstrained
# an 'unconstrained' state means the PC became symbolic -> you control execution
```

## Gotchas

- **`auto_load_libs=False`** unless you specifically need real libc behaviour; otherwise angr symbolically executes all of libc and never finishes.
- **Constrain the input charset.** Unconstrained bytes multiply the solver's work enormously.
- **Path explosion** is the normal failure mode. Symptoms: `simgr` active count growing into the thousands, memory climbing. Fixes: give explicit `find`/`avoid` addresses, use `DFS`, hook the expensive function, or give up and use z3 on the transcribed constraints.
- angr **cannot invert hashes**. If the binary computes `md5(input)` and compares, angr will run forever. Use `hashcat`.
- With PIE, addresses from your disassembler are file offsets. Add `proj.loader.main_object.mapped_base` (default `0x400000`).
- `state.posix.dumps(0)` is stdin, `dumps(1)` is stdout, `dumps(2)` is stderr.
- A symbolic length is far worse than a symbolic value. Fix the input length; try several lengths in a loop if you must.
- `explore(find=<lambda>)` re-evaluates the lambda on every state; keep it cheap.
- angr's simulated libc differs from the real one. If behaviour diverges, hook the specific function with a `SimProcedure`.
- Install is heavy and version-sensitive; always use pipx or a venv, never the system Python.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Hashing or heavy crypto in the check | `hashcat` / `john`, or read the algorithm and invert it |
| You can read the constraints | **z3 directly** - faster and far more reliable. `ctfbrain search z3` |
| Byte-independent checks | plain brute force: 256 * len tries |
| Path explosion | Manticore, Triton, or symbolic execution over a single traced path |
| You need to observe, not solve | `gdb`, `ltrace`, `strace`, Frida |
| Windows binaries | angr supports PE, but `x64dbg` scripting is often faster |
