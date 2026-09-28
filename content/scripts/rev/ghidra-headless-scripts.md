---
title: "Ghidra Headless - analyzeHeadless Recipes and Three Jython Scripts"
category: rev
subcategory: ghidra
type: script
tags: [ghidra, analyzeheadless, headless, jython, decompiler, decompinterface, ghidra-scripts, automation, batch-analysis, binaryloader, raw-binary, firmware, strings, xrefs, rename, constants, python, decompiler-export]
summary: "Every analyzeHeadless flag you actually use, plus three Python-2-and-3 Jython scripts: bulk decompile, constant-comparison hunting and rename-by-string."
tools: [ghidra, analyzeheadless, jython, python]
related: [ghidra-workflow, ghidra-cheatsheet, ida-r2-binja-workflow, triage-unknown-binary, crackme-patterns, firmware-raw-blob-loading, obfuscation-deobfuscation]
---

## What this is

Ghidra without the GUI. `analyzeHeadless` imports, analyses and runs your
scripts from a shell, so a crackme triage becomes one command and a directory of
1000 firmware images becomes one loop. The three scripts below are worth having
permanently in `$USER_HOME/ghidra_scripts` (picked up automatically) or
anywhere you point `-scriptPath` at. A script's name is its filename, and the
`# @category` comment decides where it appears in the GUI's Script Manager.

## analyzeHeadless

```sh
# analyzeHeadless ships in Ghidra's support/ directory - put it on PATH once.
export GHIDRA_HOME=/opt/ghidra_11.3_PUBLIC
export PATH="$GHIDRA_HOME/support:$PATH"

# The two positional args are ALWAYS <project_directory> <project_name>.
# Import one binary, run full auto-analysis, then run a post-script on it.
analyzeHeadless ~/ghidra-projects ctf -import ./chal \
  -scriptPath ~/ghidra_scripts \
  -postScript ExportDecompiled.py /tmp/chal.c

# Re-open the EXISTING project and re-run a script. -process matches program
# names in the project (glob allowed); -noanalysis skips re-analysing.
analyzeHeadless ~/ghidra-projects ctf -process chal -noanalysis \
  -scriptPath ~/ghidra_scripts -postScript FindConstantCompares.py /tmp/consts.txt

# -readOnly: run the script but never write changes back. Fast, and safe to
# run while you have the GUI open on the same project.
analyzeHeadless ~/ghidra-projects ctf -process 'chal*' -readOnly \
  -scriptPath ~/ghidra_scripts -postScript FindConstantCompares.py

# Throwaway: import, analyse, script, then delete the whole project again.
analyzeHeadless /tmp/gh-scratch burner -import ./chal \
  -scriptPath ~/ghidra_scripts -postScript ExportDecompiled.py /tmp/out.c \
  -deleteProject

# -overwrite replaces a program already in the project on -import.
# -okToDelete is the safety catch a script needs before it may delete programs.
analyzeHeadless ~/ghidra-projects ctf -import ./chal -overwrite -okToDelete

# -preScript runs BEFORE analysis (set analysis options, define memory blocks),
# -postScript runs after. Both take positional args after the script name.
analyzeHeadless ~/ghidra-projects ctf -import ./chal \
  -preScript SetAnalysisOptions.py aggressive \
  -postScript RenameByString.py

# A raw blob with no headers: name the loader, the base address and the CPU.
# Loader-specific options are spelled -loader-<optionName>.
analyzeHeadless ~/ghidra-projects fw -import ./firmware.bin \
  -loader BinaryLoader \
  -loader-baseAddr 0x08000000 \
  -processor ARM:LE:32:Cortex \
  -cspec default

# More -processor language IDs (see Ghidra/Processors/*/data/languages):
#   x86:LE:64:default  x86:LE:32:default  ARM:LE:32:v7  AARCH64:LE:64:v8A
#   MIPS:BE:32:default  PowerPC:BE:32:default  RISCV:LE:64:RV64G  AVR8:LE:16:atmega256
# A whole directory, recursively, in parallel, with logs. -recursive takes an
# optional depth; -max-cpu caps the analyser's thread count.
analyzeHeadless ~/ghidra-projects batch -import ./samples -recursive 3 \
  -max-cpu 4 \
  -log /tmp/ghidra.log -scriptlog /tmp/ghidra-scripts.log \
  -analysisTimeoutPerFile 300 \
  -scriptPath ~/ghidra_scripts -postScript FindConstantCompares.py

# One project per crackme, deleted as it goes. (`-import ./chal -noanalysis`
# on its own imports without analysing, for when a pre-script does the work.)
for f in ./crackmes/*; do
  analyzeHeadless /tmp/gh "$(basename "$f")" -import "$f" -deleteProject \
    -scriptPath ~/ghidra_scripts -postScript ExportDecompiled.py "/tmp/$(basename "$f").c"
done
```

## Script API basics

```python
# The globals GhidraScript injects. Valid in both Jython 2.7 and Python 3.
from __future__ import print_function

from ghidra.program.model.symbol import SourceType

prog = currentProgram                 # the Program being analysed
fm = prog.getFunctionManager()        # functions
listing = prog.getListing()           # instructions, data, comments
refman = prog.getReferenceManager()   # xrefs
memory = prog.getMemory()             # bytes and memory blocks
symtab = prog.getSymbolTable()        # labels

# Iteration: the boolean is "forward order". Also getInstructions(True) and
# getDefinedData(True) on the listing.
for f in fm.getFunctions(True):
    print("%-30s %s  %d bytes" % (f.getName(), f.getEntryPoint(),
                                  f.getBody().getNumAddresses()))

# Address arithmetic goes through the factory, not through ints.
addr = prog.getAddressFactory().getAddress("0x401000")
func = fm.getFunctionContaining(addr)
for ref in refman.getReferencesTo(addr):
    print("xref from %s (%s)" % (ref.getFromAddress(), ref.getReferenceType()))

# Input: askFile/askString/askInt pop a dialog in the GUI. In HEADLESS they
# raise unless a matching .properties file sits next to the script, so branch
# on isRunningHeadless() and read -postScript arguments instead.
if isRunningHeadless():
    args = getScriptArgs()            # -postScript Script.py a b c  ->  [a, b, c]
    target = args[0] if len(args) > 0 else "/tmp/out.txt"
else:
    target = str(askFile("Output", "Save").getAbsolutePath())

# monitor is the TaskMonitor: check it in every loop so Ctrl-C / cancel works.
monitor.setMessage("working")
if monitor.isCancelled():
    raise RuntimeError("cancelled")

# Writes (setName, setComment, createFunction) need a transaction; GhidraScript
# opens one for you. With -readOnly the transaction is simply never committed.
print(SourceType.USER_DEFINED)
```

## 1. Export decompiled C for every function

`~/ghidra_scripts/ExportDecompiled.py`

```python
# Export the decompiler's C for every function in the program.
# @category CTF.export
# @runtime Jython
from __future__ import print_function

import os

from ghidra.app.decompiler import DecompInterface, DecompileOptions

TIMEOUT_SECS = 60        # per function; raise it for huge obfuscated functions
MIN_BODY = 1             # skip zero-length thunks


def output_path():
    """-postScript ExportDecompiled.py /tmp/chal.c  ->  getScriptArgs()[0]."""
    args = getScriptArgs()
    if len(args) > 0:
        return args[0]
    if isRunningHeadless():
        return os.path.join("/tmp", "%s.c" % currentProgram.getName())
    return str(askFile("Decompiled output", "Save").getAbsolutePath())


def make_decompiler(program):
    """ONE DecompInterface for the whole program. Opening a new one per
    function costs seconds each and is the usual reason these scripts crawl."""
    ifc = DecompInterface()
    opts = DecompileOptions()
    opts.grabFromProgram(program)            # honour the project's settings
    ifc.setOptions(opts)
    ifc.setSimplificationStyle("decompile")  # full C; "normalize" is terser
    ifc.openProgram(program)
    return ifc


def main():
    path = output_path()
    program = currentProgram
    ifc = make_decompiler(program)
    fm = program.getFunctionManager()
    done, failed = 0, 0
    out = open(path, "w")
    try:
        out.write("/* %s : %d functions */\n" % (program.getName(),
                                                 fm.getFunctionCount()))
        for func in fm.getFunctions(True):
            if monitor.isCancelled():
                break
            if func.getBody().getNumAddresses() < MIN_BODY:
                continue
            monitor.setMessage("decompiling %s" % func.getName())
            res = ifc.decompileFunction(func, TIMEOUT_SECS, monitor)
            # decompileCompleted() is False on timeout AND on internal error.
            if res is None or not res.decompileCompleted():
                why = res.getErrorMessage() if res is not None else "no result"
                out.write("\n/* FAILED %s @ %s : %s */\n"
                          % (func.getName(), func.getEntryPoint(), why))
                failed += 1
                continue
            out.write("\n/* ---- %s @ %s ---- */\n"
                      % (func.getName(), func.getEntryPoint()))
            out.write(res.getDecompiledFunction().getC())
            done += 1
    finally:
        out.close()
        ifc.dispose()                        # releases the decompiler process
    print("[+] wrote %d functions (%d failed) to %s" % (done, failed, path))


main()
```

## 2. Find every comparison against a constant

The fastest route from "byte-at-a-time checker" to "expected flag bytes".

```python
# Report CMP/SUB/TEST/XOR against an immediate, with the printable character.
# @category CTF.analysis
# @runtime Jython
from __future__ import print_function

import sys

from ghidra.program.model.scalar import Scalar

# x86, ARM/AArch64 and MIPS mnemonics that fold a constant into a comparison.
INTERESTING = ("CMP", "SUB", "TEST", "XOR", "EOR", "CMN", "SLTI", "TST")
# Values that are almost always structural noise rather than flag data.
IGNORE = (0x0, 0x1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
MAX_VALUE = 0xFFFF       # a flag byte is never 0x00401234


def printable(value):
    return chr(value) if 0x20 <= value <= 0x7E else "."


def immediates(ins):
    """getOpObjects(i) returns the Register / Scalar / Address pieces of
    operand i. A Scalar is the immediate; everything else is addressing."""
    found = []
    for i in range(ins.getNumOperands()):
        for obj in ins.getOpObjects(i):
            if isinstance(obj, Scalar):
                found.append(obj.getUnsignedValue())
    return found


def main():
    args = getScriptArgs()
    sink = open(args[0], "w") if len(args) > 0 else sys.stdout
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    per_func = {}                       # name -> list of printable characters
    order = []
    hits = 0

    for ins in listing.getInstructions(True):
        if monitor.isCancelled():
            break
        mnem = ins.getMnemonicString().upper()
        if not mnem.startswith(INTERESTING):
            continue
        for value in immediates(ins):
            if value in IGNORE or value > MAX_VALUE:
                continue
            func = fm.getFunctionContaining(ins.getAddress())
            name = func.getName() if func is not None else "<orphan>"
            sink.write("%s  %-26s %-28s 0x%04x %5d '%s'\n"
                       % (ins.getAddress(), name, ins, value, value,
                          printable(value)))
            hits += 1
            if name not in per_func:
                per_func[name] = []
                order.append(name)
            per_func[name].append(printable(value))

    # The digest is the payoff: for a byte-at-a-time checker the printable
    # constants of one function, in address order, ARE the expected flag.
    sink.write("\n---- per-function digest ----\n")
    for name in order:
        chars = "".join(per_func[name])
        if len(chars.replace(".", "")) >= 4:
            sink.write("%-30s %s\n" % (name, chars))
    if sink is not sys.stdout:
        sink.close()
    print("[+] %d constant comparisons across %d functions" % (hits, len(order)))


main()
```

## 3. Rename functions after their dominant string

```python
# Rename every still-default FUN_xxxxxxxx after the string it references most.
# @category CTF.analysis
# @runtime Jython
from __future__ import print_function

import re

from ghidra.program.model.symbol import SourceType

MAX_NAME = 40
MIN_STRING = 4
NOT_IDENT = re.compile(r"[^A-Za-z0-9_]+")


def sanitise(text):
    """Ghidra tolerates almost any name, but you want a greppable C
    identifier: no spaces, no punctuation, never starting with a digit."""
    name = NOT_IDENT.sub("_", text).strip("_")
    if len(name) > MAX_NAME:
        name = name[:MAX_NAME]
    if name == "" or name[0].isdigit():
        name = "s_" + name
    return name


def defined_strings(listing):
    """Defined data only. If auto-analysis has not run, or you skipped
    'Search > For Strings', this finds nothing - that is not a bug."""
    out = []
    for data in listing.getDefinedData(True):
        if monitor.isCancelled():
            break
        if not data.hasStringDataType():
            continue
        value = data.getValue()
        if value is None:
            continue
        text = str(value)
        if len(text) >= MIN_STRING:
            out.append((data.getAddress(), text))
    return out


def main():
    listing = currentProgram.getListing()
    fm = currentProgram.getFunctionManager()
    refman = currentProgram.getReferenceManager()

    votes = {}                          # function entry point -> {string: count}
    for addr, text in defined_strings(listing):
        for ref in refman.getReferencesTo(addr):
            func = fm.getFunctionContaining(ref.getFromAddress())
            if func is None:
                continue
            entry = func.getEntryPoint()
            if entry not in votes:
                votes[entry] = {}
            votes[entry][text] = votes[entry].get(text, 0) + 1

    renamed = 0
    for entry in votes:
        func = fm.getFunctionAt(entry)
        # Never clobber a name you or the analyser already worked out.
        if func is None or not func.getName().startswith("FUN_"):
            continue
        tally = votes[entry]
        # Dominant = most references, ties broken by the longer string.
        ranked = sorted(tally.items(), key=lambda kv: (kv[1], len(kv[0])))
        new_name = "str_" + sanitise(ranked[-1][0])
        old_name = func.getName()
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
        except Exception as exc:        # DuplicateName / InvalidInput, both Java
            new_name = "%s_%s" % (new_name, entry)
            func.setName(new_name, SourceType.USER_DEFINED)
            print("[!] collision (%s), used %s" % (exc, new_name))
        print("%s  %s -> %s" % (entry, old_name, new_name))
        renamed += 1
    print("[+] renamed %d of %d string-referencing functions"
          % (renamed, len(votes)))


main()
```

Run it and keep the result:

```sh
# Without -readOnly the renames are committed to the project, so the GUI shows
# them next time you open it.
analyzeHeadless ~/ghidra-projects ctf -process chal -noanalysis \
  -scriptPath ~/ghidra_scripts -postScript RenameByString.py
```

## Gotchas

- **Jython is Python 2.7.** No f-strings, no type hints, no `yield from`. With
  `from __future__ import print_function` plus `%` formatting the scripts stay
  parseable by both interpreters, so your Python 3 linter still works. Ghidra's
  newer PyGhidra runtime is real Python 3; `# @runtime` selects it.
- **`askXxx()` throws in headless** unless a `ScriptName.properties` file sits
  beside the script. Branch on `isRunningHeadless()` and use `getScriptArgs()`,
  which is positional and always strings: everything after the script name on
  the `-postScript` line becomes an element, up to the next flag.
- **The project lock.** A project open in the GUI is locked and headless fails
  with "Unable to lock project" - close it, or import into a separate project.
- **`-process` without `-noanalysis` re-runs the full analysis** every time,
  costing minutes on a big binary. Almost always add `-noanalysis`.
- **`-readOnly` silently discards `setName`/`setComment`.** Use it for queries,
  drop it when the script is meant to change the program.
- **`-deleteProject` only works with `-import`** and removes the whole project
  directory - point it at `/tmp`, not at `~/ghidra-projects`.
- **`DecompInterface.dispose()` matters.** Each one owns a native decompiler
  process; leaking them across a `-recursive` run exhausts file descriptors.
- **Decompiler timeouts are per function.** A control-flow-flattened function
  can need 300s; raise `TIMEOUT_SECS` before concluding it is undecompilable.
- **Exit code is 0 even when a script throws.** Grep `-log` for `ERROR`, or
  make the script `print()` a sentinel line you can check for.

## References

- Ghidra project site and downloads - ghidra-sre.org
- `$GHIDRA_HOME/support/analyzeHeadlessREADME.html` - the authoritative flag
  list, shipped with every install
- Ghidra API javadoc - `$GHIDRA_HOME/docs/GhidraAPI_javadoc.zip`, especially
  `ghidra.app.script.GhidraScript`, `ghidra.program.model.listing.Listing` and
  `ghidra.app.decompiler.DecompInterface`
- The bundled scripts under `$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts`
  are the best reference for idioms the javadoc does not show
