---
title: "Ghidra - CTF Workflow"
category: rev
subcategory: ghidra
type: technique
tags: [ghidra, decompiler, retype, struct, function-signature, data-type-manager, headless, analyzeheadless, jython, ghidra-script, xrefs, symbol-tree, equate, function-diff, bookmarks, calling-convention, varargs, undefined-function, export-c]
difficulty: medium
summary: "Import, analyse, retype and export in Ghidra the way a CTF actually needs: struct recovery, signature fixing, and a headless script for bulk work."
when_to_use:
  - "You have a stripped C/C++ binary and want readable pseudo-C fast"
  - "The decompiler shows `*(int *)(param_1 + 0x18)` everywhere and you need a struct"
  - "A function decompiles as garbage: wrong stack depth, wrong arg count, missing return"
  - "You need to script Ghidra over many binaries or dump all decompiled functions to disk"
tools: [ghidra, analyzeheadless, jython, ghidra-script]
related: [triage-unknown-binary, ida-r2-binja-workflow, cpp-vtables-stl, custom-vm-bytecode, binary-patching, ghidra-cheatsheet, ghidra-headless-scripts]
---

## TL;DR

Import, run the default analysis with three options toggled, then spend your
time on exactly two things: **fixing function signatures** and **creating
structs**. Those two actions convert unreadable pointer arithmetic into
readable pseudo-C. Everything else in Ghidra is navigation. For bulk work use
`analyzeHeadless` with a Jython post-script.

## Recognise it

You are in "retype now" territory when the decompiler prints:

- `*(undefined4 *)(param_1 + 0x10)` repeated with different offsets on the same
  base pointer -> that base is a struct pointer.
- `undefined8 FUN_00101234(void)` on a function you know takes arguments.
- `local_38 [32]` indexed in a loop -> that is an array, not 8 separate locals.
- `(*(code *)(*param_1)(param_1, 3))` -> C++ vtable dispatch.
- A function body that is just `halt_baddata` or ends abruptly -> bad stack
  depth or a `__noreturn` callee Ghidra did not know about.

## Workflow

### 1. Import

GUI (Ghidra 10.x and 11.x are identical here):

1. `File -> New Project -> Non-Shared Project`, pick a directory, name it after
   the CTF. One project per CTF, one program per binary.
2. `File -> Import File...` (or drag the binary onto the project tree).
3. In the import dialog check **Format** and **Language**. Ghidra usually gets
   these right for ELF/PE/Mach-O. For a raw blob choose `Raw Binary`, then set
   Language by hand (e.g. `ARM:LE:32:v8` or `MIPS:BE:32:default`) and set the
   base address in `Options...` -> `Block Name` / `Base Address`.
4. Click `Options...` before importing if you need a non-zero image base.
5. Open the program. Ghidra offers "Analyze now?" -> say **No** the first time,
   look at the analysis options, then run it.

### 2. Analysis options worth toggling

`Analysis -> Auto Analyze '<binary>'`. The defaults are fine except:

| Option | Set to | Why |
| --- | --- | --- |
| **Decompiler Parameter ID** | **ON** | Off by default. Runs the decompiler during analysis to infer real parameter counts/types instead of guessing from the calling convention. This single toggle is the biggest quality win in Ghidra and the reason your functions show `(void)` when it is off. Costs analysis time on big binaries. |
| **Aggressive Instruction Finder** | ON for packed/obfuscated/raw | Disassembles bytes not reachable by normal flow. Recovers code hidden behind indirect jumps and in gaps. Produces false positives on data-heavy binaries, so leave OFF for clean ELFs. |
| **Windows PE x86 Propagate External Parameters** | ON for PE | Pulls parameter names/types for Win32 API calls into the decompiler. |
| **Windows x86 PE RTTI Analyzer** | ON for C++ PE | Recovers class names and vtable layout from RTTI. Turns `FUN_00401000` into `Parser::parse`. |
| **Demangler GNU / Demangler Microsoft** | ON | `_ZN6Parser5parseEPKc` -> `Parser::parse(char const*)`. |
| **Non-Returning Functions - Discovered** | ON | Stops the decompiler from continuing past `exit`/`abort`, which is a common cause of garbage tails. |
| **Shared Return Calls** | ON for optimised code | Fixes tail-call `jmp` into another function being treated as flow. |
| **Create Address Tables** | ON | Finds jump tables; essential for `switch` recovery. |
| **Stack** | ON | Stack frame analysis; needed for local variable recovery. |

After analysis finishes check `Window -> Bookmarks` for `Analysis` errors -
Ghidra records things it gave up on there.

### 3. Navigating

- `Window -> Symbol Tree` - Imports, Exports, Functions, Labels. Start in
  **Exports** (for a library) or click `entry` / `main` (for an executable).
- `Window -> Defined Strings` - sort by string, double-click a promising one,
  then `Ctrl+Shift+F` on the address to see its references. This is how you find
  the flag-check function in about fifteen seconds.
- `Ctrl+Shift+F` - **Find References To** (xrefs). Works on functions, data,
  strings, registers.
- `G` - Go To (address, symbol name, `0x401000`, `FUN_00401000`).
- `Alt+Left` / `Alt+Right` - back/forward through your navigation history.
- `Window -> Function Call Trees` - callers and callees of the current function
  as a tree. Faster than repeatedly hitting xrefs.
- `Window -> Function Graph` - CFG view. `Ctrl+Shift+G` from the listing.
- Middle-click a variable in the decompiler - highlights every occurrence in the
  function. This is the fastest way to trace a value.
- `Ctrl+E` - open the decompiler for the current function in a new tab.

### 4. Renaming and commenting

- `L` - rename a label/function/variable (in either the listing or the
  decompiler). Rename as you understand: `FUN_00101349` -> `check_flag`,
  `local_48` -> `user_input`.
- `Ctrl+L` - **set data type** on the selected variable/parameter (the
  "Retype Variable" shortcut in the decompiler; in the listing it changes the
  data type of the defined data).
- `;` - set an EOL comment at the current address.
- `Ctrl+;` - pre-comment (appears above the instruction/line).
- Plate comments (`P` in the comment dialog) - a boxed header above a function.
  Use one per function to record what you worked out.
- `Ctrl+D` - bookmark the current address (`Window -> Bookmarks` lists them).
  Bookmark the flag check, the key material, the VM dispatch loop.

### 5. Making undefined bytes into code and functions

In the listing view, on the address you want:

- `D` - **Disassemble**. Turns undefined bytes into instructions.
- `F` - **Create Function** at the current address. Use after `D` when Ghidra
  disassembled code but did not wrap it in a function.
- `C` - **Clear code bytes** (undo a bad disassembly, back to undefined).
- `Ctrl+Shift+D` - Disassemble (Restricted): follows flow but will not cross
  into already-defined data.
- If `F` refuses ("Failed to create function"), the byte range overlaps existing
  data: select the range, press `C` to clear, then `D`, then `F`.

For a jump into the middle of an instruction (a classic anti-disassembly trick):
select the bad bytes, `C` to clear, navigate to the *real* instruction boundary,
`D` there.

### 6. Fixing a function signature

Right-click the function name in the decompiler -> **Edit Function Signature**
(`F` is create-function; the signature editor has no default single-key bind in
11.x, use the right-click menu).

In that dialog you set, in one textbox, the whole C prototype:

```c
int check_flag(char *input, unsigned int len)
```

and separately:

- **Calling Convention** - `__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`
  (C++ methods on 32-bit Windows: `this` in `ECX`), `__regcall`, or `unknown`.
  Getting this wrong is the #1 cause of missing/extra parameters. On x86-64 SysV
  and Win64 the default is usually right; on 32-bit Windows it usually is not.
- **Varargs** - tick "Varargs" for `printf`-likes. Without it Ghidra shows only
  the format string and swallows the rest.
- **No Return** - tick for `exit`, `abort`, `__stack_chk_fail`, `longjmp`, or a
  custom die() function. Untick-and-retick forces the decompiler to re-flow the
  callers, which fixes truncated or nonsense function tails.
- **In Line** - force the callee body to be inlined into callers. Useful for
  tiny wrappers around a XOR.
- **Use Custom Storage** - lets you pin a parameter to a specific register.
  Needed for hand-written assembly and for obfuscators that use non-standard
  register passing. Tick it, then edit each parameter's Storage column.

The decompiler re-renders every caller immediately after you apply.

### 7. Creating and applying a struct

This is the core skill. Two routes.

**Route A - let Ghidra infer it.** In the decompiler, right-click the pointer
variable (e.g. `param_1` that is used as `*(int *)(param_1 + 0x18)`) ->
**Auto Create Structure**. Ghidra walks every dereference of that pointer in the
function, creates `astruct` in the Data Type Manager with a field at each
observed offset, and retypes the variable to `astruct *`. Then open the struct
in the Data Type Manager and rename the fields.

**Route B - write it yourself.** `Window -> Data Type Manager`, right-click your
program's folder -> `New -> Structure`. Name it, then in the editor add fields:
click a row, set DataType and Name, or use `Edit -> Insert`. Set the struct's
Size explicitly if the binary allocates a fixed size (`malloc(0x30)` -> size
0x30) and tick nothing else; Ghidra pads with `undefined` bytes so offsets stay
correct.

Then apply it: click the variable in the decompiler, `Ctrl+L` (Retype Variable),
type `MyStruct *`, Enter.

To force a type onto data in the *listing* (not a variable): `Ctrl+Shift+L`
is "Choose Data Type"; right-click -> `Data -> Choose Data Type` also works.
Right-click -> **Force Type** appears when Ghidra thinks the type does not fit
(e.g. laying a 0x30-byte struct over a region it believes is 0x20 bytes); use
it when you are sure and Ghidra is not.

**Array on the stack.** When the decompiler shows `local_48`, `local_44`,
`local_40`... being written in a loop, they are one array. Click the *first*
one, `Ctrl+L`, and enter `char[32]` (or `int[8]`). Ghidra merges the
overlapping stack slots into a single array variable and the loop becomes
`buf[i] = ...`. If it refuses because a later variable overlaps, open
`Window -> Decompiler -> Edit Function Variables`, delete the stragglers, then
retype.

**Equates for enums and constants.** Right-click a numeric constant in the
decompiler or listing -> **Set Equate** (`E`). Type a name (`SEEK_END`) or pick
an existing enum value. Define the enum first in the Data Type Manager
(`New -> Enum`) and every matching constant becomes selectable. Turns
`if (iVar1 == 3)` into `if (state == STATE_DECRYPT)` across the whole program.

### 8. Before / after - a struct retype

Raw decompiler output for a parser (analysis only, no retyping):

```c
undefined8 FUN_001012a9(long param_1,char *param_2)
{
  int iVar1;
  size_t sVar2;

  sVar2 = strlen(param_2);
  if (*(int *)(param_1 + 0x10) < (int)sVar2) {
    return 0xffffffff;
  }
  memcpy(*(void **)(param_1 + 8),param_2,sVar2);
  *(int *)(param_1 + 0x14) = (int)sVar2;
  iVar1 = *(int *)(param_1 + 0x18);
  *(int *)(param_1 + 0x18) = iVar1 + 1;
  if (*(char *)(param_1 + 0x1c) != '\0') {
    FUN_00101190(*(undefined8 *)(param_1 + 8),sVar2,*(undefined4 *)(param_1 + 0x20));
  }
  return 0;
}
```

The repeated `param_1 + <const>` dereferences with three different widths is the
tell. `Auto Create Structure` on `param_1`, rename the fields (`0x00` magic,
`0x08` buf, `0x10` cap, `0x14` len, `0x18` count, `0x1c` encrypt flag, `0x20`
key), retype `FUN_00101190` to `void xor_buf(char *buf, size_t n, uint key)`,
rename the outer function, and re-render:

```c
int parser_feed(Parser *p,char *line)
{
  size_t n;

  n = strlen(line);
  if (p->capacity < (int)n) {
    return -1;
  }
  memcpy(p->buf,line,n);
  p->len = (int)n;
  p->count = p->count + 1;
  if (p->encrypt != '\0') {
    xor_buf(p->buf,n,p->key);
  }
  return 0;
}
```

Same bytes, same analysis - the only difference is a struct and two signatures.
The `0x20` field is now obviously the XOR key you need to dump.

### 9. Fixing bad decompilation

| Symptom | Cause | Fix |
| --- | --- | --- |
| Function body truncated after a call | callee never returns, Ghidra kept flowing | Edit the callee's signature, tick **No Return** |
| `halt_baddata` in the body | bad disassembly (data in code, or misaligned) | Clear (`C`), re-disassemble (`D`) at the right boundary |
| Parameters missing / `(void)` | Decompiler Parameter ID was off | Re-run analysis with it on, or set the signature by hand |
| `unaff_EBX`, `extraout_EAX`, `in_stack_...` | Ghidra thinks a register/stack slot is live on entry | usually a wrong calling convention or a missing return type - fix the signature |
| `undefined8` return that is really `void` | inference failure | Edit Function Signature, set return type `void` |
| Stack variables look shifted by 4/8 bytes | bad stack depth at a call site | right-click the call -> `Override Signature`, or fix the callee's convention; also check `Function -> Edit Stack Frame` and the "Purge" value |
| Whole function is one giant `do { } while(true)` with a state switch | not a Ghidra bug - CFG flattening | see `obfuscation-deobfuscation` |
| A `switch` shows only one case | jump table not recovered | right-click the indirect jump -> `References -> Create Jump Table`, or run Create Address Tables |

`Function -> Edit Stack Frame` (or `Ctrl+Shift+Alt+E`) shows the raw frame:
local size, parameter offsets and **Purge** (bytes the callee pops). A wrong
purge on `__stdcall` shifts every caller's stack - fix it there.

### 10. Comparing functions

`Window -> Function Comparison`, or select two functions in the Functions
listing, right-click -> **Compare Selected Functions**. Side-by-side listing and
decompiler with differences highlighted. Uses:

- Diff a patched binary against the original to find exactly what changed.
- Diff two near-identical check routines to spot the one different constant.
- `Tools -> Program Differences` diffs two whole *programs* (byte, code unit,
  symbol and comment differences) - use this for a "here is the patched version"
  task.

`Window -> Version Tracking` is the heavyweight option for matching functions
between a stripped and an unstripped build of the same program (correlators:
Exact Bytes, Exact Instructions, Symbol Name, Reference). Worth it when you have
a debug build of the same library.

### 11. Exporting C

`File -> Export Program...`, Format = **C/C++**. Options let you include or skip
the header file. You get one `.c` with every decompiled function - greppable,
diffable, and pasteable into a compiler for a re-implementation.

For a single function: in the decompiler pane, right-click -> `Copy` after
`Select All`, or use the headless script below to dump functions selectively.

## Headless analyzer

`analyzeHeadless` is in `<GHIDRA_INSTALL>/support/`. It creates or reuses a
project, imports, analyses, and runs your scripts, with no GUI.

```sh
# Create project ./ghidra_proj/ctf, import chall, analyse, run a post-script.
# -import       : file (or directory) to import
# -postScript   : run AFTER auto-analysis (use -preScript to run before)
# -scriptPath   : where your .py/.java scripts live
# -deleteProject: throw the project away when done (omit to keep it)
# -max-cpu      : cap analysis threads so your laptop stays usable
"$GHIDRA_HOME/support/analyzeHeadless" ./ghidra_proj ctf \
    -import ./chall \
    -scriptPath ./scripts \
    -postScript dump_decomp.py /tmp/chall_decomp.c \
    -max-cpu 4 \
    -deleteProject

# Re-run a script against an ALREADY imported program (no re-analysis):
"$GHIDRA_HOME/support/analyzeHeadless" ./ghidra_proj ctf \
    -process chall \
    -noanalysis \
    -scriptPath ./scripts \
    -postScript find_xor_keys.py

# Batch: import a whole directory of binaries and analyse each one.
"$GHIDRA_HOME/support/analyzeHeadless" ./ghidra_proj batch \
    -import ./binaries/ -recursive \
    -scriptPath ./scripts -postScript dump_decomp.py /tmp/out

# Force a language for a raw blob (list IDs with: -? or the GUI import dialog).
"$GHIDRA_HOME/support/analyzeHeadless" ./ghidra_proj fw \
    -import ./firmware.bin \
    -processor "ARM:LE:32:v8" \
    -loader BinaryLoader -loader-baseAddr 0x08000000 \
    -scriptPath ./scripts -postScript dump_decomp.py /tmp/fw.c
```

Notes: `$GHIDRA_HOME` is the install root (the directory containing
`ghidraRun`). On a fresh install run `analyzeHeadless` once with no arguments to
print the full usage. Ghidra 11 ships Jython 2.7 for `.py` scripts; Java and
PyGhidra (CPython 3, `-jar` free, Ghidra 11.2+) are the alternatives.

### Post-script: dump every decompiled function

Save as `scripts/dump_decomp.py`. It is Jython (Python 2 syntax rules) but
written so CPython 3 parses it too - `print()` function form, no `print` stmt.

```python
# Ghidra headless post-script: decompile every function to one .c file.
# Usage (headless):  -postScript dump_decomp.py /tmp/out.c
# Usage (GUI):       drop in your script dir, run from the Script Manager
#                    (it then writes to ghidra_dump.c in the project dir).
# Jython 2.7 compatible AND valid Python 3 syntax.
# @category CTF

from __future__ import print_function

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def get_output_path():
    args = getScriptArgs()
    if len(args) > 0:
        return args[0]
    return "ghidra_dump.c"


def make_decompiler(program):
    """Set up a DecompInterface with a 60-second per-function budget."""
    iface = DecompInterface()
    iface.openProgram(program)
    return iface


def main():
    program = getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    iface = make_decompiler(program)
    out_path = get_output_path()

    fm = program.getFunctionManager()
    total = 0
    failed = 0

    handle = open(out_path, "w")
    handle.write("/* decompiled by Ghidra headless: %s */\n"
                 % program.getName())

    for func in fm.getFunctions(True):          # True = forward order
        if func.isThunk():
            continue                            # thunks are noise
        entry = func.getEntryPoint()
        res = iface.decompileFunction(func, 60, monitor)
        if not res.decompileCompleted():
            failed += 1
            handle.write("/* FAILED %s @ %s : %s */\n"
                         % (func.getName(), entry, res.getErrorMessage()))
            continue
        code = res.getDecompiledFunction().getC()
        handle.write("\n/* ---- %s @ %s ---- */\n" % (func.getName(), entry))
        handle.write(code)
        total += 1

    handle.close()
    iface.dispose()
    print("[+] wrote %d functions (%d failed) to %s"
          % (total, failed, out_path))


main()
```

### Post-script: label functions that reference a string, and find XOR keys

Save as `scripts/find_xor_keys.py`. Two jobs CTFs need constantly: locate the
function behind a message, and list every immediate XOR constant.

```python
# Ghidra script: (1) print the functions that reference flag-ish strings,
#                (2) list every XOR-with-immediate instruction and its constant.
# Jython 2.7 compatible AND valid Python 3 syntax.
# @category CTF

from __future__ import print_function

from ghidra.program.model.symbol import RefType

KEYWORDS = ["flag", "correct", "wrong", "password", "key", "nope", "ctf{"]


def function_at(program, addr):
    return program.getFunctionManager().getFunctionContaining(addr)


def report_string_xrefs(program):
    listing = program.getListing()
    refmgr = program.getReferenceManager()
    print("=== strings of interest and their callers ===")
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        value = data.getValue()
        if value is None:
            continue
        text = str(value).lower()
        if not any(k in text for k in KEYWORDS):
            continue
        addr = data.getAddress()
        refs = refmgr.getReferencesTo(addr)
        for ref in refs:
            if ref.getReferenceType() == RefType.DATA or ref.isMemoryReference():
                src = ref.getFromAddress()
                func = function_at(program, src)
                fname = func.getName() if func is not None else "<no function>"
                print("  %-40s <- %s @ %s" % (str(value)[:40], fname, src))


def report_xor_immediates(program):
    print("=== xor reg, imm ===")
    listing = program.getListing()
    inst_iter = listing.getInstructions(True)
    seen = {}
    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnem = inst.getMnemonicString().lower()
        if mnem not in ("xor", "eor"):
            continue
        for i in range(inst.getNumOperands()):
            for obj in inst.getOpObjects(i):
                # Scalar operands are the immediates we care about.
                if hasattr(obj, "getUnsignedValue"):
                    val = obj.getUnsignedValue()
                    if val == 0:
                        continue            # xor reg,reg / zeroing idiom
                    func = function_at(program, inst.getAddress())
                    fname = func.getName() if func is not None else "?"
                    key = (fname, val)
                    if key in seen:
                        continue
                    seen[key] = True
                    print("  %-30s 0x%x  @ %s"
                          % (fname, val, inst.getAddress()))


def main():
    program = getCurrentProgram()
    print("[*] program: %s" % program.getName())
    report_string_xrefs(program)
    report_xor_immediates(program)
    print("[+] done")


main()
```

Run either from the GUI (`Window -> Script Manager`, refresh, double-click) or
headless with `-postScript`.

## Variants & pitfalls

- **Decompiler Parameter ID is off by default** and it is the difference between
  usable and useless output. Turn it on for every CTF binary.
- **Ghidra's `undefined4`/`undefined8` are not types**, they are "I do not know,
  this many bytes". Every one you replace with a real type improves the whole
  function.
- **Retyping propagates.** Fixing one callee's signature can fix five callers at
  once. Work bottom-up: leaf helpers first, then the functions that call them.
- **Do not fight the stack for C++**. Turn on the RTTI analyzer, let it build
  the vtable structs, then retype `this`. See `cpp-vtables-stl`.
- **Undo is per-transaction and cheap** (`Ctrl+Z`). Experiment with retypes
  freely.
- **`Force Type` can corrupt your listing** if the struct really does not fit -
  it overwrites neighbouring defined data. Check the bytes after applying.
- **Jython is Python 2.7.** No f-strings, no `pathlib`. If you need CPython 3
  use PyGhidra (Ghidra 11.2+) or Ghidrathon.
- **Headless leaves lock files** if it crashes: delete `<project>.rep/.ghidraLock`
  before rerunning.
- **`-deleteProject` only applies when the project was created by that run.**
  It will not delete a pre-existing project.
- **Analysis is not idempotent for free** - re-running auto-analysis after you
  retyped things can undo inference, but it will not delete your manual names,
  comments or applied types. Manual work survives; inferred work is recomputed.
- **Big Go/Rust binaries** take a long time. Use `-max-cpu` and consider
  disabling `Aggressive Instruction Finder` and the demanglers you do not need.

## Tools

- `ghidraRun` - the GUI (`ghidraRun.bat` on Windows).
- `support/analyzeHeadless` - the headless analyzer.
- `Window -> Script Manager` - run/edit scripts; `Ctrl+Shift+N` for a new one.
- **Ghidrathon** - CPython 3 scripting inside Ghidra.
- **PyGhidra** - official CPython bridge shipped with Ghidra 11.2+.
- **GhidraEmu / ghidra-emu-fun** - emulate a function inside Ghidra.
- **GolangAnalyzerExtension**, **GoReSym** - restore Go symbols before analysis.
- **ret-sync** - sync Ghidra's cursor with a live gdb/WinDbg session.
- `rz-ghidra` / `r2ghidra` - the Ghidra decompiler as a rizin/radare2 plugin.

## References

- Ghidra project site and documentation, ghidra-sre.org.
- Ghidra source repository, github.com/NationalSecurityAgency/ghidra - the
  `Ghidra/Features/Decompiler` and `Ghidra/Features/Base/ghidra_scripts`
  directories are the best script examples.
- Ghidra built-in help: `Help -> Contents`, "Decompiler" and "Headless
  Analyzer" chapters (the headless chapter documents every flag used above).
- Ghidra API javadoc, shipped in `<GHIDRA_INSTALL>/docs/GhidraAPI_javadoc.zip`.
</content>
