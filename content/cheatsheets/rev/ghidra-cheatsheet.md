---
title: "Ghidra - Shortcuts, Analysis Options and Headless"
category: rev
subcategory: ghidra
type: cheatsheet
tags: [ghidra, decompiler, shortcuts, hotkeys, struct, retype, headless, analyzeheadless, jython, ghidra-script, data-type-manager, function-signature, patch-instruction, version-tracking, raw-binary]
summary: "Every Ghidra shortcut worth memorising, the analysis options to change, the analyzeHeadless command lines, and a working string-xref script."
tools: [ghidra, analyzeHeadless, jython]
related: [ghidra-workflow, ghidra-headless-scripts, ida-r2-binja-workflow, radare2-cheatsheet, binary-patching, firmware-raw-blob-loading]
---

## Navigation

```
G                 # Go to an address, symbol or expression (accepts 0x401136, main, FUN_00401136)
Ctrl+Shift+E      # Go to the next/previous... (Navigation shortcuts dialog)
Alt+Left          # Back in navigation history
Alt+Right         # Forward
Ctrl+Alt+Left     # Previous function
Ctrl+Alt+Right    # Next function
Home / End        # Start / end of the program
Ctrl+Home         # Top of the current function
Down / Up         # Next / previous code unit
Ctrl+D            # Toggle a bookmark at the current address
Ctrl+Shift+D      # Bookmarks window
Ctrl+E            # Go to the next instruction of the same kind
Tab               # Move between the Listing and the Decompiler (with matching cursor)
Ctrl+Shift+F      # Show all references TO the current symbol (Find References To)
Ctrl+Shift+G      # (Listing) Patch Instruction
Middle-click      # Highlight all occurrences of the token under the cursor
```

## Listing (disassembly view)

```
L                 # Rename the label/function at the cursor
;                 # Add an EOL comment
Alt+;             # (or right-click > Comments) pre-comment
Ctrl+;            # Plate comment (banner above a function)
D                 # Disassemble at the cursor
F                 # Create a function at the cursor
C                 # Clear code bytes back to undefined  (NOTE: in IDA, C means "make code")
Ctrl+Shift+Q      # Delete the function at the cursor
B                 # Set the byte-alignment / define byte data
T                 # Choose Data Type (opens the type chooser)
P                 # Define a pointer
A                 # Define a string (ASCII)
Shift+A           # Define a string with a chosen encoding
[ or Ctrl+[       # Create an array from the selection
'                 # Define a char
Shift+;           # Set equate (give a constant a symbolic name, e.g. an enum member)
E                 # Set equate on the scalar operand under the cursor
Ctrl+Shift+E      # Remove equate
Ctrl+Alt+F        # Set function signature (Edit Function)
Ctrl+L            # (Listing) Retype the data at the cursor
Y                 # (Decompiler and Listing) Edit function signature
Ctrl+Shift+N      # Rename a namespace/class
Ctrl+Shift+A      # Analyze from the cursor
Ctrl+Shift+I      # Instruction Info (opcode bytes, mnemonic, operands)
Ctrl+Shift+C      # Copy special (as bytes, as C array, as python bytes)
Ctrl+M            # Toggle the Memory Map window
F                 # (in Function Graph) fit the graph to the window
Space             # Toggle between the Listing and the Function Graph view
```

## Decompiler window

```
L                 # Rename a variable / function
Ctrl+L            # Retype a variable (the single most valuable Ghidra hotkey)
Y                 # Edit Function Signature (return type, calling convention, params, varargs)
;                 # Comment
Ctrl+Shift+G      # Not available here - patch from the Listing
Ctrl+Alt+H        # Highlight forward slice (where does this value go?)
Ctrl+Alt+Shift+H  # Highlight backward slice (where did this value come from?)
Ctrl+Alt+D        # Highlight the def of the token under the cursor
Middle-click      # Highlight all uses of a token
Ctrl+Shift+F      # Find references to the symbol
Right-click > "Split Out As New Variable"     # when Ghidra merged two distinct variables
Right-click > "Merge with ..."                # when it split one variable into several
Right-click > "Force Type"                    # force a cast that Ghidra resists
Right-click > "Auto Create Structure"         # from a pointer parameter: build a struct
Right-click > "Auto Fill in Structure"        # extend an existing struct from usage
Right-click > "Commit Params/Return"          # freeze the signature so callers update
Right-click > "Override Signature"            # at a call site, for indirect/varargs calls
Right-click > "Isolate"                       # stop a variable from being merged
Right-click > "Secondary Highlight"           # a persistent colour for one variable
Ctrl+Shift+S      # Export the decompiled function
```

## Structures and data types

```
# Data Type Manager (bottom-left dock). Right-click your program's folder:
#   New > Structure...    create an empty struct
#   New > Enum...         name the magic constants
#   New > Typedef / Union / Function Definition
# In the structure editor:
#   Insert/Delete rows, set each field's DataType, Name and Comment
#   "Undefined" fields are padding; set the Size field to grow the struct
#   Right-click a field > "Set Data Type" (or just type the type name in the cell)
# Apply the struct:
#   Listing: put the cursor on the data, press Ctrl+L, type the struct name
#   Decompiler: put the cursor on the variable, press Ctrl+L, type "MyStruct *"
# Parse C headers into the type database:
#   File > Parse C Source...  (add include paths, then Parse to Program)
# Archive shared types:
#   Data Type Manager > right-click > New File Archive / Open File Archive (.gdt)
```

```
# Applying a struct fixes the decompiler output:
#   before:  *(int *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + 1;
#   after:   ctx->counter = ctx->counter + 1;
```

## Function signatures

```
# Y or Ctrl+Alt+F in either window opens "Edit Function"
#   Function Name, Calling Convention (__cdecl/__stdcall/__fastcall/__thiscall),
#   Return Type, Parameters (add/remove/reorder), Varargs checkbox,
#   "No Return" (for exit/abort - stops the decompiler from inventing fallthrough code)
# Set a function as noreturn without the dialog:
#   right-click the function in the Symbol Tree > "Set Function Non-Returning"
# Fix the calling convention for a custom-ABI function:
#   Edit Function > Calling Convention > __regcall / unknown, then set storage manually
#   via "Use Custom Storage" and assigning a register to each parameter.
```

## Searching

```
Search > Memory...                  # byte/string/regex search across memory (Ctrl+Shift+M)
Search > Program Text...            # search comments, labels, instructions, decompiled text
Search > For Strings...             # (re)run the string finder with a chosen minimum length
Search > For Instruction Patterns   # build a masked instruction pattern and search for it
Search > For Direct References      # who references this address
Search > For Matching Instructions  # compare against another open program
Window > Defined Strings            # THE window: every string + its address, double-click
Window > Symbol Table               # all symbols, sortable and filterable
Window > Function Call Trees        # incoming/outgoing call tree for the current function
Window > Bytes                      # a hex editor view (also where you patch bytes)
Window > Memory Map                 # blocks, permissions, base addresses; add RAM/MMIO here
Window > Script Manager             # run/edit Ghidra scripts
Window > Data Type Manager
Window > Function Graph             # CFG view
Window > Decompile                  # if you closed it
Window > Console                    # script output
```

## Analysis options worth changing

```
# Analysis > Auto Analyze... (or Analysis > One Shot > ... to rerun a single analyzer)
Decompiler Parameter ID       # ON: propagates parameter types across calls. Slow but worth it.
Aggressive Instruction Finder # ON for stripped/obfuscated code and shellcode-like blobs
Demangler GNU / Demangler Microsoft / Demangler Rust / Demangler Swift   # ON for C++/Rust
Objective-C 2 Class / Message # ON for Mach-O ObjC binaries
Windows x86 PE RTTI Analyzer  # ON to recover C++ class names from MSVC RTTI
Windows x86 PE Exception Handling  # ON: recovers function boundaries from .pdata
Non-Returning Functions - Discovered / Known   # ON: stops bogus fallthrough after exit()
Shared Return Calls           # ON for tail-call-heavy code (Go, Rust)
Stack                         # ON: recovers local variables
Create Address Tables         # ON: finds jump tables
Embedded Media                # OFF unless you need it (slow)
ASCII Strings                 # tune the minimum length for noisy binaries
Reference / Data Reference    # ON
Call Convention ID            # ON
# After changing options: Analysis > One Shot > <analyzer> re-runs just that one
```

## Import options

```
File > Import File...
  Format:   auto-detected, or "Raw Binary" for a headerless blob
  Language: <arch>:<endian>:<bits>:<variant>, e.g.
              x86:LE:64:default        x86:LE:32:default
              ARM:LE:32:v8             ARM:LE:32:Cortex     (Cortex-M = Thumb)
              AARCH64:LE:64:v8A        MIPS:BE:32:default
              PowerPC:BE:32:default    RISCV:LE:64:RV64GC
  Options...:  Base Address (critical for raw blobs)
File > Add To Program...      # load a second file into the same program (e.g. a library)
File > Export Program...      # "Original File" writes a real binary back out (for patching)
                              # "C/C++" exports the decompilation; "ASCII" the listing
```

## Patching

```
Ctrl+Shift+G                  # Patch Instruction: type "NOP" or "JMP 0x401200"
Window > Bytes, then Ctrl+Shift+E (Enable Editing)   # raw byte editing in the hex view
File > Export Program > Original File                # write the patched binary to disk
# Ghidra keeps the instruction length: pad short replacements with NOP yourself.
```

## Diffing and version tracking

```
Tools > Program Differences     # byte/code-unit diff between two open programs
Window > Function Diff          # side-by-side decompiler diff of two functions (10.2+)
File > Open, then Tools > Version Tracking    # full BinDiff-style matching between programs
   Correlators worth running: Exact Function Bytes Match, Exact Function Instructions,
   Exact Symbol Name Match, Similar Symbol Name, Data Reference Match
```

## The headless analyzer

```sh
# Location: <ghidra_install>/support/analyzeHeadless
# Syntax:   analyzeHeadless <project_dir> <project_name> [options]
export GHIDRA=/opt/ghidra

# 1. Import + analyse + run a post-script, then keep the project
$GHIDRA/support/analyzeHeadless /tmp/proj ctf \
    -import ./chall \
    -scriptPath ~/ghidra_scripts \
    -postScript DumpStrings.py

# 2. Same but throw the project away when finished (one-shot analysis)
$GHIDRA/support/analyzeHeadless /tmp/proj ctf \
    -import ./chall -postScript ExportDecompiled.py /tmp/out.c \
    -deleteProject

# 3. Re-run a script against something already in a project (no re-analysis)
$GHIDRA/support/analyzeHeadless /tmp/proj ctf \
    -process 'chall' -noanalysis \
    -scriptPath ~/ghidra_scripts -postScript FindConstants.py

# 4. Read-only: do not save changes back to the project
$GHIDRA/support/analyzeHeadless /tmp/proj ctf -process 'chall' -readOnly \
    -postScript ExportDecompiled.py

# 5. A whole directory of binaries, recursively
$GHIDRA/support/analyzeHeadless /tmp/proj ctf \
    -import ./samples -recursive \
    -postScript Triage.py -deleteProject

# 6. A raw firmware blob: choose the loader, processor and base address
$GHIDRA/support/analyzeHeadless /tmp/proj fw \
    -import ./firmware.bin \
    -loader BinaryLoader \
    -loader-baseAddr 0x08000000 \
    -processor 'ARM:LE:32:Cortex' \
    -postScript VectorTable.py

# 7. Pass arguments to the script (read them with getScriptArgs())
$GHIDRA/support/analyzeHeadless /tmp/proj ctf -process 'chall' \
    -postScript Rename.py check_flag 0x401136

# 8. Pre-script (runs BEFORE analysis - use it to set the memory map or options)
$GHIDRA/support/analyzeHeadless /tmp/proj ctf -import ./chall \
    -preScript SetupMemory.py -postScript Dump.py

# 9. Useful extras
#   -max-cpu 4              limit analysis threads
#   -log /tmp/ghidra.log    write the log somewhere you can read it
#   -scriptlog /tmp/s.log   script output separately
#   -okToDelete             allow -deleteProject on a pre-existing project
#   -overwrite              replace a program of the same name in the project
#   -noanalysis             import without analysing (fast, for scripted triage)
#   -analysisTimeoutPerFile 300
#   -propertiesPath ./props
#   -commit "message"       for shared (Ghidra Server) projects
```

```sh
# Run a script against many binaries and collect the output
for f in samples/*; do
  $GHIDRA/support/analyzeHeadless /tmp/proj batch -import "$f" \
      -scriptPath ~/ghidra_scripts -postScript StringXrefs.py \
      -deleteProject 2>/dev/null | grep '^\[out\]'
done
```

## Script API essentials

```
# Scripts live in ~/ghidra_scripts (or anywhere given with -scriptPath).
# In the GUI: Window > Script Manager > "Create New Script" (Java or Python/Jython).
# Ghidra 11+ also supports PyGhidra (real CPython 3) via the Ghidrathon-style bridge;
# the classic in-tree interpreter is Jython 2.7, so write Python-2-compatible code.

currentProgram                 # the Program object
currentAddress                 # where the cursor is (GUI) / the entry (headless)
currentSelection               # the selected range, or None
getScriptArgs()                # list of strings passed after -postScript Name.py
getFunctionManager()           # currentProgram.getFunctionManager()
getListing()                   # currentProgram.getListing()
getReferenceManager()          # currentProgram.getReferenceManager()
getMemory()                    # currentProgram.getMemory()
getSymbolTable()               # currentProgram.getSymbolTable()
toAddr(0x401136)               # int -> Address
getFunctionAt(addr) / getFunctionContaining(addr)
getInstructionAt(addr) / getInstructionAfter(ins)
getDataAt(addr) / getDataAfter(data)
getBytes(addr, n)
createLabel(addr, name, True)
setEOLComment(addr, "text") / setPlateComment(addr, "text")
askString / askFile / askAddress / askInt     # GUI prompts; in headless they read args
monitor                        # a TaskMonitor to pass to long operations
println("...")                 # goes to the console and the headless log
```

## A working script: strings with xrefs + auto-rename

Save as `~/ghidra_scripts/StringXrefs.py` and run it from the Script Manager, or headless
with `-postScript StringXrefs.py`.

```python
# StringXrefs.py - list every defined string with its referencing functions, then
# rename each unnamed function after its most distinctive string reference.
#
# Ghidra script (Jython 2.7). Written to parse under both Python 2 and Python 3.
#
# @category CTF
# @runtime Jython
from __future__ import print_function

import re

from ghidra.program.model.data import StringDataType
from ghidra.program.model.symbol import SourceType

MIN_LEN = 4
BORING = re.compile(r"^(?:[%\s\W]{0,3}|GCC|GLIBC|__|\.|/lib|/usr|libc)", re.I)
SAFE = re.compile(r"[^A-Za-z0-9_]+")


def defined_strings():
    """Yield (address, text) for every defined string in the program."""
    listing = currentProgram.getListing()
    data = listing.getDefinedData(True)
    out = []
    while data.hasNext():
        item = data.next()
        dtype = item.getDataType()
        if isinstance(dtype, StringDataType) or "string" in dtype.getName().lower():
            value = item.getValue()
            if value is None:
                continue
            text = str(value)
            if len(text) >= MIN_LEN:
                out.append((item.getAddress(), text))
    return out


def referencing_functions(addr):
    """Every function that references `addr`."""
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    funcs = []
    for ref in ref_mgr.getReferencesTo(addr):
        fn = fm.getFunctionContaining(ref.getFromAddress())
        if fn is not None:
            funcs.append((ref.getFromAddress(), fn))
    return funcs


def sanitise(text):
    """Turn a string literal into a legal, readable symbol name."""
    name = SAFE.sub("_", text.strip())[:32].strip("_")
    if not name:
        return None
    if name[0].isdigit():
        name = "s_" + name
    return name


def main():
    strings = defined_strings()
    print("[*] %d defined string(s) of length >= %d" % (len(strings), MIN_LEN))

    # Pass 1: report every string with its xrefs
    candidates = {}
    for addr, text in strings:
        refs = referencing_functions(addr)
        if not refs:
            continue
        shown = text if len(text) <= 60 else text[:57] + "..."
        print("[out] %s  %r" % (addr, shown))
        for from_addr, fn in refs:
            print("         <- %s in %s @ %s" % (from_addr, fn.getName(), fn.getEntryPoint()))
            if BORING.match(text):
                continue
            entry = fn.getEntryPoint()
            best = candidates.get(entry)
            # prefer the longest non-boring string referenced by this function
            if best is None or len(text) > len(best[1]):
                candidates[entry] = (fn, text)

    # Pass 2: rename functions that still have a default name
    renamed = 0
    for entry in candidates:
        fn, text = candidates[entry]
        current = fn.getName()
        if not (current.startswith("FUN_") or current.startswith("SUB_")):
            continue
        name = sanitise(text)
        if name is None:
            continue
        new_name = "str_" + name
        try:
            fn.setName(new_name, SourceType.USER_DEFINED)
            print("[ren] %s -> %s" % (current, new_name))
            renamed += 1
        except Exception as exc:
            print("[!] could not rename %s: %s" % (current, exc))

    print("[*] renamed %d function(s)" % renamed)


main()
```

```sh
# Run it headless over a binary and keep only the interesting lines
$GHIDRA/support/analyzeHeadless /tmp/proj ctf -import ./chall \
    -scriptPath ~/ghidra_scripts -postScript StringXrefs.py -deleteProject \
    2>/dev/null | grep -E '^\[(out|ren)\]'
```

## Miscellaneous

```
# Show the raw bytes of every instruction in the Listing
Browser Field Formatter (the "Edit the listing fields" icon) > Instruction/Data > Bytes
# Change the decompiler's C style / max payload
Edit > Tool Options > Decompiler > Analysis / Display
#   "Maximum payload size (MBytes)" - raise it for huge functions that fail to decompile
#   "Decompiler Timeout (seconds)" - raise it for obfuscated code
# Colour a background (mark visited code)
Right-click in the Listing > Colors > Set Background Color
# Undo/redo analysis changes
Ctrl+Z / Ctrl+Shift+Z
# Save the program (analysis results) to the project
Ctrl+S
# Shared projects
File > New Project > Shared Project (needs a Ghidra Server)
# Extensions (plugins: ghidra-wasm, GolangAnalyzerExtension, ret-sync, Ghidrathon)
File > Install Extensions..., then restart
```

## References

- Ghidra Help (F1 in the tool) - "Listing", "Decompiler", "Data Type Manager",
  "Importing Files" and "Headless Analyzer" chapters.
- `<ghidra>/support/analyzeHeadless` with no arguments prints the full option list.
- `<ghidra>/Ghidra/Features/Base/ghidra_scripts/` - dozens of official example scripts.
