---
title: "Tool - Ghidra"
category: rev
subcategory: disassembler
type: tool
tags: [ghidra, decompiler, disassembler, reverse-engineering, nsa, headless, analyzeheadless, sre, p-code, scripting, jython, function-signature, struct, rev]
summary: "The free NSA reverse-engineering suite: multi-architecture decompiler, scriptable, with a headless mode for automation."
related: [rev-triage, radare2, jadx, pwn-triage]
---

## What it is

Ghidra is a full software reverse engineering suite with a decompiler that handles x86/x64, ARM/AArch64, MIPS, PowerPC, RISC-V, SPARC, AVR, 6502, and more. It is the default choice when you do not have IDA Pro. It has a project model, a type/struct editor, a scripting API (Java and Jython), and a headless analyzer for batch work.

## Install

```sh
# macOS
brew install --cask ghidra
# Linux: download the release zip from the official site and unzip; it is a self-contained Java app
# Kali/Parrot package it
sudo apt install ghidra
# Requires a JDK 17+ on PATH
java -version
# launch
ghidraRun          # or ./ghidraRun from the unpacked directory
```

## The invocations that matter

```sh
# 1. headless: import a binary, run auto-analysis, keep the project
analyzeHeadless /tmp/proj MyProject -import ./chal

# 2. headless with a post-analysis script (the automation workhorse)
analyzeHeadless /tmp/proj MyProject -import ./chal -postScript DumpFunctions.py

# 3. re-open an existing project's program and run a script without re-importing
analyzeHeadless /tmp/proj MyProject -process chal -postScript DumpDecomp.py -noanalysis

# 4. batch a directory of binaries
analyzeHeadless /tmp/proj Batch -import ./samples/ -recursive -postScript Strings.py

# 5. dump the decompilation of every function to stdout
analyzeHeadless /tmp/proj P -import ./chal -postScript DecompileAll.py -scriptPath ./scripts

# 6. delete and reimport cleanly (Ghidra caches aggressively)
analyzeHeadless /tmp/proj P -import ./chal -overwrite

# 7. give the analyzer more memory for a large binary
export MAXMEM=8G   # or edit ghidraRun / analyzeHeadless support/launch.properties
```

A minimal post-script that dumps decompiled C (`scripts/DecompileAll.py`, Jython):
```python
# Ghidra Jython post-script: prints the decompilation of every function.
# @category CTF
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for func in currentProgram.getFunctionManager().getFunctions(True):
    res = ifc.decompileFunction(func, 60, monitor)
    if res.decompileCompleted():
        print("/* ==== %s @ %s ==== */" % (func.getName(), func.getEntryPoint()))
        print(res.getDecompiledFunction().getC())
```

In the GUI, the keys that matter:

| Key | Action |
|---|---|
| `L` | rename the symbol under the cursor |
| `Ctrl+L` | retype a variable (this is what makes decompilation readable) |
| `;` | add a comment |
| `G` | go to an address or symbol |
| `Ctrl+Shift+E` | edit the function signature |
| `Ctrl+Shift+G` | find references to the current address |
| `S` | create a string at the cursor |
| `D` / `C` | disassemble / clear code |
| `F` | create a function at the cursor |
| `Ctrl+E` | show the decompiler for the current function |
| `Search -> For Strings` | the first thing to do on any binary |
| `Window -> Defined Strings` / `Symbol Tree` / `Function Call Graph` | navigation |

Workflow that gets results fastest: find the success/failure string -> right-click -> References to -> land in the checking function -> retype variables until the decompilation reads like C -> transcribe the check into z3 or Python.

## Gotchas

- The decompiler **guesses** types and calling conventions. If the output looks nonsensical, fix the function signature (`Ctrl+Shift+E`) before believing anything.
- Undefined arrays show as `local_38` blobs; retype them to `char[N]` and the logic becomes obvious.
- Ghidra sometimes misses functions in stripped binaries. Use `Analysis -> Aggressive Instruction Finder`, or define functions manually with `F`.
- Auto-analysis on a large Go/Rust binary takes many minutes. Start it and work on something else.
- Headless mode with `-import` on an existing program fails unless you pass `-overwrite` or use `-process`.
- The version of Jython is 2.7; write Python 2-compatible script syntax, or use the Java API / PyGhidra where available.
- Stack variable offsets in the decompiler are relative to the frame, not to `rsp` at the overflow point. Verify the offset with `cyclic` in gdb rather than trusting the listing.
- Changing a type does not re-run analysis on callers; re-decompile them explicitly.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Better decompilation quality | IDA Pro / Binary Ninja (commercial); `retdec` (free, weaker) |
| Fast CLI triage | `radare2` / `rizin` + `pdg` (rizin's Ghidra decompiler plugin), `objdump -d -M intel` |
| .NET binary | `dnSpy` / `ILSpy` - never use Ghidra for managed code |
| Java / Android | `jadx`, `cfr`, `procyon` |
| Go binary with no symbols | `GoReSym`, `redress`, then re-import |
| A quick look at one function | `objdump -d --start-address=0x... --stop-address=0x...` |
| Scripting against many binaries | `angr`'s CFG, or `radare2`'s `r2pipe` (much lighter than Ghidra headless) |
