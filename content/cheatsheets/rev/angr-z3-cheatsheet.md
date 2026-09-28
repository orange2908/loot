---
title: "angr and z3 - Recipes Side by Side"
category: rev
subcategory: symbolic-execution
type: cheatsheet
tags: [angr, z3, symbolic-execution, claripy, simprocedure, constraint-solving, bitvector, solver, exploration-technique, veritesting, state-explosion, hooks, smt, flag-solver]
summary: "angr recipes (states, explore, hooks, SimProcedures, file/stdin) next to the equivalent z3 recipes (bitvectors, arrays, all-solutions, uniqueness)."
tools: [angr, z3, claripy, python]
related: [angr-symbolic-execution, z3-constraint-solving, angr-template, z3-flagsolver-template, custom-vm-bytecode, obfuscation-deobfuscation]
---

## Install

```sh
# angr pulls in claripy, pyvex, cle and z3 - always use a virtualenv
python3 -m venv .venv && . .venv/bin/activate
pip install angr
pip install z3-solver            # standalone z3, also installed as an angr dependency
python3 -c "import angr, z3; print(angr.__version__, z3.get_version_string())"
```

## angr: loading

```python
import angr, claripy

# The standard load: skip libc so calls become SimProcedures (much faster)
proj = angr.Project("./chall", auto_load_libs=False)

# Keep the real libraries (needed when the challenge uses a rare library function)
proj = angr.Project("./chall", auto_load_libs=True)

# Force a load base (PIE binaries are mapped at 0x400000 by default)
proj = angr.Project("./chall", main_opts={"base_addr": 0x400000}, auto_load_libs=False)

# Raw blob with no headers
proj = angr.Project("fw.bin", main_opts={
    "backend": "blob", "arch": "ARMEL", "base_addr": 0x8000000, "entry_point": 0x8000100})

proj.arch                     # <Arch AMD64 (LE)>
proj.entry                    # entry point address
proj.filename
proj.loader.main_object.min_addr      # load base - add to Ghidra offsets for PIE
proj.loader.main_object.max_addr
proj.loader.shared_objects            # dict of loaded libraries
proj.loader.find_symbol("main").rebased_addr
proj.kb.functions                     # after CFG generation
```

## angr: states

```python
# Start at the entry point, symbolic argv
flag = claripy.BVS("flag", 8 * 32)
state = proj.factory.entry_state(args=["./chall", flag])

# Start anywhere (skips initialisation - fill memory to avoid unconstrained reads)
state = proj.factory.blank_state(addr=0x401136, add_options={
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
})

# Call a function directly with concrete and symbolic arguments
state = proj.factory.call_state(0x401136, 0x500000, 32, prototype="int f(char*, int)")

# Full initialisation including the dynamic loader (slow, rarely needed)
state = proj.factory.full_init_state(args=["./chall"])

# Registers and memory
state.regs.rdi = 0x500000
state.regs.pc
state.memory.store(0x500000, flag)
state.memory.load(0x500000, 32)
state.stack_push(claripy.BVV(0, 64))
state.mem[0x500000].char.array(32).concrete
```

## angr: symbolic input

```python
# --- stdin ---------------------------------------------------------------
flag = claripy.BVS("flag", 8 * 32)
state = proj.factory.entry_state(stdin=flag)          # simplest form

# With full control over the file semantics (length, EOF behaviour)
simfile = angr.SimFileStream(name="stdin", content=flag, has_end=False)
state = proj.factory.entry_state(stdin=simfile)

# --- argv ----------------------------------------------------------------
state = proj.factory.entry_state(args=["./chall", flag])

# --- a file on disk ------------------------------------------------------
simfile = angr.SimFile("flag.txt", content=flag, size=32)
state = proj.factory.entry_state(fs={"flag.txt": simfile})

# --- a buffer already in memory (function-level) --------------------------
state = proj.factory.blank_state(addr=0x401136)
buf = 0x500000
state.memory.store(buf, flag)
state.regs.rdi = buf
state.regs.rsi = 32

# --- constraints on the input --------------------------------------------
for byte in flag.chop(8):
    state.solver.add(byte >= 0x20, byte <= 0x7E)          # printable
    # or an explicit charset:
    # state.solver.add(claripy.Or(*[byte == c for c in b"abcdef0123456789{}_"]))
state.solver.add(flag.chop(8)[0] == ord("C"))             # known prefix
state.solver.add(flag.get_bytes(0, 4) == b"CTF{")         # same, nicer
```

## angr: exploring

```python
simgr = proj.factory.simulation_manager(state)

# By address
simgr.explore(find=0x4011a5, avoid=(0x4011b8, 0x401200))

# By output predicate (robust against PIE and refactoring)
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),
    avoid=lambda s: b"Wrong" in s.posix.dumps(1),
)

# Find several solutions
simgr.explore(find=0x4011a5, num_find=3)

# Manual stepping with a custom condition
while simgr.active:
    simgr.step()
    for s in simgr.active:
        if b"Correct" in s.posix.dumps(1):
            print(s.solver.eval(flag, cast_to=bytes))

# Inspect the stashes
simgr                     # <SimulationManager with 1 found, 12 avoid, 3 active>
simgr.found[0]
simgr.active
simgr.deadended
simgr.errored
simgr.unconstrained       # PC became symbolic - often means a bug (or an exploit!)
simgr.stashes.keys()
simgr.move(from_stash="active", to_stash="stash", filter_func=lambda s: s.addr > 0x500000)
simgr.drop(stash="avoid")          # free memory
simgr.prune()

# Extract the answer
sol = simgr.found[0]
print(sol.solver.eval(flag, cast_to=bytes))
print(sol.posix.dumps(0))          # everything that was read from stdin
print(sol.posix.dumps(1))          # everything printed
```

## angr: hooks and SimProcedures

```python
# --- Replace an address range with Python ---------------------------------
@proj.hook(0x401180, length=5)          # length = bytes of original code to skip
def skip_check(state):
    state.regs.rax = 1

# Skip a call entirely (length = the size of the call instruction)
proj.hook(0x4011c3, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), length=5)

# Hook with a simple lambda-style function
proj.hook(0x401200, lambda state: state.regs.__setattr__("rax", 0), length=5)

# --- Replace a whole function by symbol -----------------------------------
class FakeStrlen(angr.SimProcedure):
    def run(self, s):
        return 32                       # always 32 - avoids a symbolic-length loop

proj.hook_symbol("strlen", FakeStrlen())

class CheckHash(angr.SimProcedure):
    """Replace an expensive hash with a symbolic summary."""
    def run(self, buf, length):
        data = self.state.memory.load(buf, 32)
        # return a fresh symbolic value constrained however you like
        out = claripy.BVS("hash", 32)
        self.state.solver.add(out != 0)
        return out

proj.hook_symbol("sha256_digest", CheckHash())

# --- Reuse angr's own library implementations -----------------------------
proj.hook_symbol("printf", angr.SIM_PROCEDURES["libc"]["printf"]())
angr.SIM_PROCEDURES["libc"].keys()      # what is available

# --- Hook an unsupported instruction --------------------------------------
proj.hook(0x401234, lambda s: None, length=2)        # NOP out 2 bytes
```

## angr: performance and state explosion

```python
import angr

opts = {
    angr.options.LAZY_SOLVES,                       # defer constraint checks
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,    # silence warnings, deterministic
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    angr.options.SIMPLIFY_EXPRS,
}
state = proj.factory.entry_state(add_options=opts)

# Unicorn engine: run concrete stretches natively instead of symbolically
state = proj.factory.entry_state(add_options=angr.options.unicorn)

# Exploration techniques
simgr.use_technique(angr.exploration_techniques.DFS())                    # memory-friendly
simgr.use_technique(angr.exploration_techniques.Veritesting())            # merges paths
simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=16))       # cap loop counts
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=2048))
simgr.use_technique(angr.exploration_techniques.Spiller())                # page states to disk
simgr.use_technique(angr.exploration_techniques.Explorer(find=0x4011a5))
simgr.use_technique(angr.exploration_techniques.Threading(threads=4))

# Veritesting via the simulation manager constructor
simgr = proj.factory.simulation_manager(state, veritesting=True)

# Keep the state count bounded by hand
while simgr.active:
    simgr.step()
    if len(simgr.active) > 50:
        simgr.stash(from_stash="active", to_stash="deferred",
                    filter_func=lambda s: True)
        simgr.active.append(simgr.deferred.pop())

# CFG (needed for some techniques; CFGFast is the one you want)
cfg = proj.analyses.CFGFast()
cfg = proj.analyses.CFGEmulated(keep_state=True)          # slow, more precise
func = proj.kb.functions["main"]
func.block_addrs_set
```

```python
# Logging: turn angr's noise down (or up, when debugging a stuck run)
import logging
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("angr.sim_manager").setLevel(logging.INFO)   # see step counts
```

## angr: inspecting and debugging a run

```python
# Breakpoint-style callbacks on symbolic events
def on_mem_write(state):
    print(hex(state.addr), state.inspect.mem_write_address,
          state.inspect.mem_write_expr)

state.inspect.b("mem_write", when=angr.BP_AFTER, action=on_mem_write)
state.inspect.b("call", when=angr.BP_BEFORE,
                action=lambda s: print("call", s.inspect.function_address))
state.inspect.b("constraints", when=angr.BP_AFTER,
                action=lambda s: print("added", s.inspect.added_constraints))

# Where has this state been?
state.history.bbl_addrs.hardcopy          # list of basic block addresses
[hex(a) for a in state.history.bbl_addrs]
state.history.jump_guards.hardcopy        # the branch conditions taken
len(state.solver.constraints)

# Disassemble what angr sees
proj.factory.block(0x401136).pp()
proj.factory.block(0x401136).vex.pp()     # the VEX IR
proj.factory.block(0x401136).capstone.insns
```

## z3: the core API

```python
from z3 import (And, Array, BitVec, BitVecVal, BitVecSort, Concat, Distinct, Extract,
                If, Int, LShR, Not, Or, RotateLeft, RotateRight, Select, SignExt, Solver,
                Store, Sum, UDiv, ULE, ULT, URem, Xor, ZeroExt, sat, set_param, simplify,
                unsat)

s = Solver()
x = BitVec("x", 32)                 # a 32-bit machine word - NOT Int
y = BitVecVal(0x41, 8)              # a constant
s.add(x ^ 0xDEADBEEF == 0x12345678)
print(s.check())                    # sat / unsat / unknown
m = s.model()
print(m[x], hex(m[x].as_long()))
```

```python
# Bit operations - the ones people get wrong
LShR(x, 3)          # LOGICAL right shift (unsigned >>)  <-- usually what C does on unsigned
x >> 3              # ARITHMETIC right shift (sign-propagating)
x << 3              # shift left (wraps at the bit width)
ZeroExt(24, b)      # 8-bit -> 32-bit, zero-filled
SignExt(24, b)      # 8-bit -> 32-bit, sign-extended (C's `char` promotion!)
Extract(7, 0, x)    # low byte (high_bit, low_bit, expr) - inclusive
Concat(a, b)        # a is the HIGH part
RotateLeft(x, 3)    # rol
RotateRight(x, 3)   # ror
UDiv(x, 3) / URem(x, 3)     # unsigned division/modulo ( / and % are SIGNED )
ULT(x, y) / ULE(x, y)       # unsigned comparison ( < and <= are SIGNED )
```

```python
# Boolean structure
And(a, b, c)
Or(a, b)
Not(a)
Xor(a, b)
If(cond, then_expr, else_expr)          # ternary, works on BitVecs
Distinct(a, b, c)                       # pairwise !=
Sum([a, b, c])                          # works for BitVecs of equal width
```

```python
# Arrays (table lookups, memory models)
sbox = Array("sbox", BitVecSort(8), BitVecSort(8))
for i, v in enumerate(TABLE):                     # TABLE = the 256 bytes from .rodata
    sbox = Store(sbox, i, v)
s.add(Select(sbox, flag[0]) == 0x9A)

# Simpler when the table is concrete: build a nested If chain, or index in Python
def lookup(table, idx):
    expr = BitVecVal(table[-1], 8)
    for i in range(len(table) - 1, -1, -1):
        expr = If(idx == i, BitVecVal(table[i], 8), expr)
    return expr
```

## z3: the flag-array pattern

```python
from z3 import BitVec, Solver, And, sat

LEN = 32
flag = [BitVec("f%d" % i, 8) for i in range(LEN)]
s = Solver()

# printable ASCII
for c in flag:
    s.add(And(c >= 0x20, c <= 0x7E))

# known format
for i, ch in enumerate(b"CTF{"):
    s.add(flag[i] == ch)
s.add(flag[LEN - 1] == ord("}"))

# ... the challenge's constraints ...
s.add(flag[0] ^ flag[1] == 0x11)

assert s.check() == sat
m = s.model()
print(bytes(m[c].as_long() for c in flag))
```

```python
# Enumerate ALL solutions by blocking each model
def all_solutions(solver, variables, limit=16):
    from z3 import Or, sat
    out = []
    while len(out) < limit and solver.check() == sat:
        model = solver.model()
        out.append(bytes(model[v].as_long() for v in variables))
        solver.add(Or([v != model[v] for v in variables]))
    return out

# Prove a solution is unique: after adding the blocking clause, check() must be unsat
```

```python
# Performance
from z3 import Solver, SolverFor, set_param
s = SolverFor("QF_BV")          # a specialised bitvector tactic - often much faster
s.set("timeout", 60000)         # milliseconds
set_param("parallel.enable", True)
set_param("parallel.threads.max", 8)
print(s.statistics())
print(s.sexpr())                # dump the SMT-LIB2 problem (feed to another solver)
# push/pop for incremental solving
s.push(); s.add(extra); print(s.check()); s.pop()
```

## Side by side: the same challenge, two ways

The target: `for i in range(16): if ((inp[i] ^ 0x5a) + i) & 0xff != enc[i]: fail()`

```python
# --- z3: model the arithmetic directly (fast, exact) ----------------------
from z3 import BitVec, Solver, And, sat

ENC = [0x19, 0x1C, 0x1D, 0x21, 0x2B, 0x35, 0x27, 0x2D,
       0x34, 0x32, 0x3B, 0x3F, 0x36, 0x3E, 0x40, 0x27]
flag = [BitVec("f%d" % i, 8) for i in range(16)]
s = Solver()
for i, c in enumerate(flag):
    s.add(And(c >= 0x20, c <= 0x7E))
    s.add(((c ^ 0x5A) + i) & 0xFF == ENC[i])
print(s.check(), bytes(s.model()[c].as_long() for c in flag) if s.check() == sat else "")
```

```python
# --- angr: never look at the arithmetic at all ---------------------------
import angr, claripy

proj = angr.Project("./chall", auto_load_libs=False)
flag = claripy.BVS("flag", 8 * 16)
state = proj.factory.entry_state(stdin=flag)
for byte in flag.chop(8):
    state.solver.add(byte >= 0x20, byte <= 0x7E)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
              avoid=lambda s: b"Wrong" in s.posix.dumps(1))
if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

| | angr | z3 |
|---|---|---|
| Input | the binary | your transcription of the logic |
| Effort | minutes to write | minutes to hours to transcribe |
| Fails on | loops, big state spaces, syscalls, crypto | nothing it can express, but you must express it |
| Best for | small self-contained checkers | constraint systems, big keyspaces, custom VMs |
| Debugging | painful (state explosion, unconstrained) | easy (unsat core, print the model) |
| Escape hatch | hook the slow part, then it is really z3 | emulate instead of transcribing (Unicorn) |

## Diagnosing failures

```python
# angr: nothing found
len(simgr.active), len(simgr.deadended), len(simgr.errored)
simgr.errored[0].error          # the exception
simgr.errored[0].state          # reproduce it
[hex(a) for a in simgr.deadended[0].history.bbl_addrs]   # where did it actually go?
# Memory blowup: use DFS + LoopSeer + drop the avoid stash
# Unconstrained states: PC went symbolic. Usually a missing hook or a wrong start state.

# z3: unsat
s.check()                        # unsat means your model is wrong or over-constrained
print(s.unsat_core())            # only works if you add constraints with assumptions:
#   p = Bool("c17"); s.assert_and_track(constraint, p)
# Drop constraints one by one until it flips to sat - the last one removed is the bug.
# unknown: raise the timeout, switch to SolverFor("QF_BV"), or simplify the model.
```

## Common pitfalls

```
# z3
- Using Int instead of BitVec: no wraparound, wrong answers for xor/shift code.
- `>>` on a BitVec is ARITHMETIC. Use LShR for unsigned code.
- `/` and `%` and `<` are SIGNED. Use UDiv/URem/ULT for unsigned code.
- Forgetting that C promotes `char` with sign extension - use SignExt when the source
  type is signed char.
- `==` builds a constraint object; `if x == y:` is always truthy. Use `s.add(x == y)`.
- Python ints in mixed expressions are fine, but `0xff & c` keeps the BitVec width.
- Not checking uniqueness: the first model may be a false solution.

# angr
- auto_load_libs=True makes everything 50x slower. Default it to False.
- blank_state without ZERO_FILL_* produces "unconstrained" warnings and bogus paths.
- Addresses from Ghidra on a PIE binary need the angr base (0x400000) applied.
- explore(find=int) breaks if the binary is rebuilt; prefer the stdout predicate.
- A symbolic strlen/scanf length explodes instantly - hook it with a fixed length.
- Hash functions (md5/sha) are effectively unsolvable; hook them out.
- `state.solver.eval(x)` gives ONE solution; use eval_upto(x, n) to see more.
- cast_to=bytes only works on a BV whose size is a multiple of 8.
```

## References

- angr documentation ("Core Concepts", "Symbolic Execution", "Exploration Techniques",
  "SimProcedures") and the `angr-doc` examples repository.
- Z3 Python API documentation (`z3.Solver`, `z3.BitVec`, the `z3.z3` module docstrings).
- `help(z3)` and `dir(angr.options)` are the authoritative local references.
