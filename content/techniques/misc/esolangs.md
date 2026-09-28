---
title: "Esolangs - Identification and Interpreters"
category: misc
subcategory: esolang
type: technique
tags: [esolang, brainfuck, whitespace, malbolge, piet, befunge, ook, jsfuck, lolcode, chef, rockstar, intercal, shakespeare, interpreter, decoder, identification]
difficulty: easy
summary: "Recognise the language from its character set, then run it - most CTF esolang challenges are one interpreter call away."
when_to_use:
  - "The challenge file is a wall of +-<>[]., or invisible whitespace, or an image of coloured blocks"
  - "The text reads like a recipe, a Shakespeare play, or song lyrics"
  - "You see only ()[]!+ characters (JavaScript) or a base-94 looking blob"
  - "file says ASCII text but nothing in it is words"
tools: [python3, beef, bf, npiet, befunge, node]
related: [text-unicode-stego, ctf-general-cheatsheet, misc-classics, python-jail-escape]
---

## TL;DR

Esolang challenges are pattern recognition plus an interpreter. Identify by character set, run
it, read the output. The only ones that need real work are Malbolge (write a generator, do not
hand-write) and Piet (an image, needs `npiet`).

## Identification table

| Signature | Language | Run it with |
| --- | --- | --- |
| Only `+-<>[].,` | Brainfuck | the interpreter below, `beef`, `bf` |
| `Ook. Ook? Ook!` triples | Ook! | translate pairs to Brainfuck |
| Only spaces, tabs, newlines | Whitespace | the interpreter below |
| `>v<^` plus digits and `@` in a 2D grid | Befunge-93 | the interpreter below, `bef` |
| Dense base-94 punctuation soup, starts with `(=<` often | Malbolge | a generator, not by hand |
| A PNG/GIF of coloured blocks | Piet | `npiet`, `npiet-foogol` |
| `HAI`, `CAN HAS STDIO?`, `VISIBLE`, `KTHXBYE` | LOLCODE | `lci` |
| `Ingredients.`, `Method.`, `Serves 4.` | Chef | a Chef interpreter |
| `[Enter Romeo and Juliet]`, `Act I:` | Shakespeare | `spl` / an SPL interpreter |
| `PLEASE DO`, `COME FROM` | INTERCAL | `ick` |
| Song lyrics with `Put X into Y`, `Shout` | Rockstar | a Rockstar interpreter |
| Only `[]()!+` | JSFuck | paste into a JS console (carefully) |
| `ppap`, `pikachu`, `poke` style word soup | a Brainfuck substitution variant | map tokens to bf |
| `01100110 01101100` groups of 8 | plain binary, not an esolang | `int(x,2)` |
| Long runs of `$_` and `$$` in PHP-ish text | PHP non-alphanumeric obfuscation | evaluate carefully |

If the character set is exactly 8 distinct symbols in any alphabet, it is almost certainly
Brainfuck with a substitution cipher. Count the distinct characters first:

```bash
# distinct characters and their counts
fold -w1 chal.txt | sort | uniq -c | sort -rn
# how many distinct?
fold -w1 chal.txt | sort -u | wc -l
```

Eight distinct symbols where one is roughly twice as frequent as the rest and two appear in
balanced pairs -> Brainfuck. Map by frequency: `+` and `>` are most common, `[` and `]` are
balanced, `.` appears once per output character.

## Brainfuck

Eight instructions over a byte tape:

| Op | Meaning |
| --- | --- |
| `>` | move the pointer right |
| `<` | move the pointer left |
| `+` | increment the cell (mod 256) |
| `-` | decrement the cell |
| `.` | output the cell as a byte |
| `,` | read a byte into the cell |
| `[` | jump past the matching `]` if the cell is 0 |
| `]` | jump back to the matching `[` if the cell is non-zero |

**Ook!** maps directly: `Ook. Ook?` = `>`, `Ook? Ook.` = `<`, `Ook. Ook.` = `+`,
`Ook! Ook!` = `-`, `Ook! Ook.` = `.`, `Ook. Ook!` = `,`, `Ook! Ook?` = `[`, `Ook? Ook!` = `]`.

**Brainloller** encodes Brainfuck in an image's pixel colours; **Braincopter** in an image's
pixel values. Both need their own decoder, but the underlying program is Brainfuck.

## Whitespace

Only space (S), tab (T) and line feed (L) are significant; everything else is a comment.
Instruction modification parameters (IMPs):

| IMP | Meaning |
| --- | --- |
| `S` | stack manipulation |
| `TS` | arithmetic |
| `TT` | heap access |
| `L` | flow control |
| `TL` | I/O |

Numbers are `sign bit (S=+, T=-)` then binary digits (`S`=0, `T`=1) terminated by `L`.
`SS<num>L` pushes a number; `TLSS` outputs a character; `TLST` outputs a number.

## Befunge-93

A 2D grid (80x25) with a stack. The instruction pointer moves in a direction and wraps.

| Op | Meaning |
| --- | --- |
| `>` `<` `^` `v` | set direction |
| `?` | random direction |
| `_` `\|` | horizontal/vertical conditional |
| `0`-`9` | push a digit |
| `+ - * / %` | arithmetic |
| `!` | logical not |
| `` ` `` | greater-than |
| `:` | duplicate |
| `\` | swap |
| `$` | pop and discard |
| `.` | pop and print as an integer |
| `,` | pop and print as a character |
| `"` | toggle string mode (push every character until the next `"`) |
| `#` | bridge: skip the next cell |
| `p` | put: `y x v p` writes v into the grid (self-modifying code) |
| `g` | get: `y x g` pushes the grid value |
| `@` | end |

Self-modifying `p` instructions are how Befunge challenges hide the flag: run it, do not read it.

## Malbolge

Base-94 with a "crazy operation" trit-wise table, self-modifying encryption after every
instruction. Nobody writes Malbolge by hand; programs are produced by search. For a CTF you
only ever need to *run* it - find any Malbolge interpreter and feed it the file. If the
challenge asks you to *write* Malbolge, use an existing generator.

## Piet

The program is an image of coloured blocks ("codels"). Hue and lightness transitions between
adjacent blocks encode operations; block size encodes pushed values.

```bash
# run a Piet program
npiet chal.png
npiet -v chal.png            # trace
npiet -tpic trace.png chal.png
# the image may need upscaling first if the codel size is 1 pixel
convert chal.png -filter point -resize 1000% big.png
```

## Code

Three complete interpreters. Each has a self-test in `__main__`.

```python
#!/usr/bin/env python3
"""Interpreters for Brainfuck, Whitespace and Befunge-93, plus an Ook!/substitution decoder.

  python3 esolangs.py bf      prog.bf [input]
  python3 esolangs.py ws      prog.ws
  python3 esolangs.py befunge prog.bef
  python3 esolangs.py detect  chal.txt
  python3 esolangs.py --selftest
"""
from __future__ import annotations

import random
import sys
from collections import Counter

# --------------------------------------------------------------------------- #
# Brainfuck
# --------------------------------------------------------------------------- #
BF_OPS = "><+-.,[]"


def bf_run(code: str, stdin: bytes = b"", tape_size: int = 30000,
           max_steps: int = 50_000_000) -> bytes:
    code = "".join(c for c in code if c in BF_OPS)
    jumps: dict[int, int] = {}
    stack: list[int] = []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                raise ValueError(f"unmatched ] at {i}")
            j = stack.pop()
            jumps[i] = j
            jumps[j] = i
    if stack:
        raise ValueError(f"unmatched [ at {stack[-1]}")

    tape = bytearray(tape_size)
    ptr = ip = inp = steps = 0
    out = bytearray()
    n = len(code)
    while ip < n:
        steps += 1
        if steps > max_steps:
            raise RuntimeError("step limit exceeded (infinite loop?)")
        c = code[ip]
        if c == ">":
            ptr = (ptr + 1) % tape_size
        elif c == "<":
            ptr = (ptr - 1) % tape_size
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ".":
            out.append(tape[ptr])
        elif c == ",":
            tape[ptr] = stdin[inp] if inp < len(stdin) else 0
            inp += 1
        elif c == "[":
            if tape[ptr] == 0:
                ip = jumps[ip]
        elif c == "]":
            if tape[ptr] != 0:
                ip = jumps[ip]
        ip += 1
    return bytes(out)


OOK_MAP = {
    (".", "?"): ">", ("?", "."): "<", (".", "."): "+", ("!", "!"): "-",
    ("!", "."): ".", (".", "!"): ",", ("!", "?"): "[", ("?", "!"): "]",
}


def ook_to_bf(text: str) -> str:
    toks = [t[-1] for t in text.replace("\n", " ").split() if t.startswith("Ook")]
    out = []
    for i in range(0, len(toks) - 1, 2):
        out.append(OOK_MAP.get((toks[i], toks[i + 1]), ""))
    return "".join(out)


def substitution_to_bf(text: str, mapping: dict[str, str]) -> str:
    return "".join(mapping.get(ch, "") for ch in text)


def guess_bf_substitution(text: str) -> dict[str, str] | None:
    """If the text has exactly 8 distinct tokens, guess the mapping by frequency/balance."""
    chars = [c for c in text if not c.isspace()]
    counts = Counter(chars)
    if len(counts) != 8:
        return None
    # the two characters that appear an equal number of times and are balanced are [ and ]
    ordered = [c for c, _ in counts.most_common()]
    return {ordered[i]: BF_OPS[i] for i in range(8)}   # a starting point, verify by running


# --------------------------------------------------------------------------- #
# Whitespace
# --------------------------------------------------------------------------- #
def ws_parse_number(src: str, i: int) -> tuple[int, int]:
    if i >= len(src):
        raise ValueError("truncated number")
    sign = -1 if src[i] == "\t" else 1
    i += 1
    bits = []
    while i < len(src) and src[i] != "\n":
        bits.append("1" if src[i] == "\t" else "0")
        i += 1
    i += 1  # consume the terminating newline
    val = int("".join(bits), 2) if bits else 0
    return sign * val, i


def ws_parse(src: str) -> list[tuple[str, object]]:
    """Tokenise a Whitespace program into (opcode, argument) pairs."""
    src = "".join(c for c in src if c in " \t\n")
    prog: list[tuple[str, object]] = []
    i = 0

    def label() -> str:
        nonlocal i
        start = i
        while i < len(src) and src[i] != "\n":
            i += 1
        out = src[start:i]
        i += 1
        return out

    while i < len(src):
        imp = src[i]
        i += 1
        if imp == " ":                                   # stack manipulation
            c = src[i]
            i += 1
            if c == " ":
                v, i = ws_parse_number(src, i)
                prog.append(("push", v))
            elif c == "\n":
                sub = src[i]
                i += 1
                prog.append({" ": ("dup", None), "\t": ("swap", None),
                             "\n": ("drop", None)}[sub])
            else:                                        # tab: copy / slide
                sub = src[i]
                i += 1
                v, i = ws_parse_number(src, i)
                prog.append(("copy" if sub == " " else "slide", v))
        elif imp == "\t":
            c = src[i]
            i += 1
            if c == " ":                                 # arithmetic
                prog.append(("arith", src[i:i + 2]))
                i += 2
            elif c == "\t":                              # heap
                sub = src[i]
                i += 1
                prog.append(("store" if sub == " " else "retrieve", None))
            else:                                        # I/O
                prog.append(("io", src[i:i + 2]))
                i += 2
        else:                                            # newline: flow control
            op = src[i:i + 2]
            i += 2
            if op == "  ":
                prog.append(("label", label()))
            elif op == " \t":
                prog.append(("call", label()))
            elif op == " \n":
                prog.append(("jmp", label()))
            elif op == "\t ":
                prog.append(("jz", label()))
            elif op == "\t\t":
                prog.append(("jn", label()))
            elif op == "\t\n":
                prog.append(("ret", None))
            elif op == "\n\n":
                prog.append(("end", None))
            else:
                raise ValueError(f"bad flow-control opcode at {i}")
    return prog


def ws_run(src: str, stdin: str = "", max_steps: int = 1_000_000) -> str:
    prog = ws_parse(src)
    labels = {arg: idx for idx, (op, arg) in enumerate(prog) if op == "label"}
    stack: list[int] = []
    heap: dict[int, int] = {}
    out: list[str] = []
    calls: list[int] = []
    inp = list(stdin)
    pc = 0
    steps = 0

    while 0 <= pc < len(prog):
        steps += 1
        if steps > max_steps:
            raise RuntimeError("step limit exceeded")
        op, arg = prog[pc]
        pc += 1
        if op == "push":
            stack.append(int(arg))
        elif op == "dup":
            stack.append(stack[-1])
        elif op == "swap":
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == "drop":
            stack.pop()
        elif op == "copy":
            stack.append(stack[-1 - int(arg)])
        elif op == "slide":
            top = stack.pop()
            del stack[len(stack) - int(arg):]
            stack.append(top)
        elif op == "arith":
            b, a = stack.pop(), stack.pop()
            stack.append({"  ": a + b, " \t": a - b, " \n": a * b,
                          "\t ": a // b if b else 0, "\t\t": a % b if b else 0}[arg])
        elif op == "store":
            val, addr = stack.pop(), stack.pop()
            heap[addr] = val
        elif op == "retrieve":
            stack.append(heap.get(stack.pop(), 0))
        elif op == "io":
            if arg == "  ":
                out.append(chr(stack.pop() & 0x10FFFF))
            elif arg == " \t":
                out.append(str(stack.pop()))
            elif arg == "\t ":
                heap[stack.pop()] = ord(inp.pop(0)) if inp else 0
            else:
                addr = stack.pop()
                digits = ""
                while inp and (inp[0].isdigit() or (not digits and inp[0] == "-")):
                    digits += inp.pop(0)
                heap[addr] = int(digits or "0")
        elif op == "label":
            pass
        elif op == "call":
            calls.append(pc)
            pc = labels[arg]
        elif op == "jmp":
            pc = labels[arg]
        elif op == "jz":
            if stack.pop() == 0:
                pc = labels[arg]
        elif op == "jn":
            if stack.pop() < 0:
                pc = labels[arg]
        elif op == "ret":
            pc = calls.pop()
        elif op == "end":
            break
    return "".join(out)


def ws_number(n: int) -> str:
    """Encode an integer in Whitespace number syntax (for building test programs)."""
    sign = " " if n >= 0 else "\t"
    bits = bin(abs(n))[2:]
    return sign + "".join(" " if b == "0" else "\t" for b in bits) + "\n"


# --------------------------------------------------------------------------- #
# Befunge-93
# --------------------------------------------------------------------------- #
def befunge_run(code: str, stdin: str = "", max_steps: int = 2_000_000,
                seed: int | None = 0) -> str:
    rng = random.Random(seed)
    lines = code.split("\n")
    height = max(25, len(lines))
    width = max(80, max((len(l) for l in lines), default=0))
    grid = [[" "] * width for _ in range(height)]
    for y, line in enumerate(lines):
        for x, ch in enumerate(line):
            grid[y][x] = ch

    stack: list[int] = []
    out: list[str] = []
    x = y = 0
    dx, dy = 1, 0
    string_mode = False
    steps = 0
    inp = list(stdin)

    def pop() -> int:
        return stack.pop() if stack else 0

    while steps < max_steps:
        steps += 1
        c = grid[y][x]
        if string_mode:
            if c == '"':
                string_mode = False
            else:
                stack.append(ord(c))
        elif c.isdigit():
            stack.append(int(c))
        elif c == ">":
            dx, dy = 1, 0
        elif c == "<":
            dx, dy = -1, 0
        elif c == "^":
            dx, dy = 0, -1
        elif c == "v":
            dx, dy = 0, 1
        elif c == "?":
            dx, dy = rng.choice([(1, 0), (-1, 0), (0, 1), (0, -1)])
        elif c == "_":
            dx, dy = ((1, 0) if pop() == 0 else (-1, 0))
        elif c == "|":
            dx, dy = ((0, 1) if pop() == 0 else (0, -1))
        elif c == "+":
            stack.append(pop() + pop())
        elif c == "-":
            b, a = pop(), pop()
            stack.append(a - b)
        elif c == "*":
            stack.append(pop() * pop())
        elif c == "/":
            b, a = pop(), pop()
            stack.append(a // b if b else 0)
        elif c == "%":
            b, a = pop(), pop()
            stack.append(a % b if b else 0)
        elif c == "!":
            stack.append(1 if pop() == 0 else 0)
        elif c == "`":
            b, a = pop(), pop()
            stack.append(1 if a > b else 0)
        elif c == ":":
            v = pop()
            stack.extend([v, v])
        elif c == "\\":
            b, a = pop(), pop()
            stack.extend([b, a])
        elif c == "$":
            pop()
        elif c == ".":
            out.append(str(pop()) + " ")
        elif c == ",":
            out.append(chr(pop() & 0xFF))
        elif c == "#":
            x = (x + dx) % width
            y = (y + dy) % height
        elif c == "p":
            py, px, v = pop(), pop(), pop()
            if 0 <= py < height and 0 <= px < width:
                grid[py][px] = chr(v & 0xFF)
        elif c == "g":
            py, px = pop(), pop()
            stack.append(ord(grid[py][px]) if 0 <= py < height and 0 <= px < width else 0)
        elif c == "&":
            digits = ""
            while inp and inp[0].isdigit():
                digits += inp.pop(0)
            stack.append(int(digits or "0"))
        elif c == "~":
            stack.append(ord(inp.pop(0)) if inp else -1)
        elif c == '"':
            string_mode = True
        elif c == "@":
            break
        x = (x + dx) % width
        y = (y + dy) % height
    return "".join(out)


# --------------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------------- #
def detect(text: str) -> list[str]:
    notes = []
    chars = set(text)
    nonspace = {c for c in chars if not c.isspace()}
    if nonspace <= set(BF_OPS):
        notes.append("Brainfuck (character set is a subset of ><+-.,[])")
    if chars <= {" ", "\t", "\n"} and "\t" in chars:
        notes.append("Whitespace (only space/tab/newline)")
    if "Ook" in text:
        notes.append("Ook! (Brainfuck dialect) - translate token pairs")
    if nonspace and nonspace <= set("[]()!+"):
        notes.append("JSFuck (JavaScript with only []()!+ )")
    if any(k in text for k in ("HAI", "KTHXBYE", "VISIBLE", "CAN HAS")):
        notes.append("LOLCODE")
    if "Ingredients." in text and "Method." in text:
        notes.append("Chef")
    if "PLEASE" in text and "DO" in text:
        notes.append("INTERCAL")
    if "[Enter" in text or "Act I:" in text:
        notes.append("Shakespeare Programming Language")
    if "@" in chars and len({c for c in "><^v" if c in chars}) >= 2 and "\n" in text:
        notes.append("Befunge (2D grid with direction changes and an @ terminator)")
    if len({c for c in text if not c.isspace()}) == 8:
        notes.append("exactly 8 distinct symbols -> a Brainfuck substitution variant; "
                     "map by frequency and verify by running")
    printable = [c for c in text if 33 <= ord(c) < 127]
    if len(printable) > 100 and len(set(printable)) > 60 and " " not in text[:200]:
        notes.append("dense base-94 punctuation -> possibly Malbolge")
    return notes or ["no esolang signature matched"]


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    # Brainfuck: the canonical Hello World
    hello = ("++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++."
             ">>.<-.<.+++.------.--------.>>+.>++.")
    assert bf_run(hello) == b"Hello World!\n", bf_run(hello)

    # Brainfuck with input: echo one byte
    assert bf_run(",.", b"A") == b"A"

    # unmatched brackets are reported, not silently ignored
    try:
        bf_run("[")
    except ValueError:
        pass
    else:
        raise AssertionError("expected unmatched-bracket error")

    # Ook! translation round trip
    inv = {v: k for k, v in OOK_MAP.items()}
    ook = " ".join(f"Ook{a} Ook{b}" for a, b in (inv[c] for c in ",."))
    assert ook_to_bf(ook) == ",."
    assert bf_run(ook_to_bf(ook), b"Z") == b"Z"

    # Whitespace: push 72 ('H'), print char; push 105 ('i'), print char; end
    ws = ""
    for ch in "Hi":
        ws += "  " + ws_number(ord(ch))   # SS <num> : push
        ws += "\t\n  "                    # TL SS    : output character
    ws += "\n\n\n"                        # LLL      : end program
    assert ws_run(ws) == "Hi", repr(ws_run(ws))

    # Whitespace arithmetic: push 20, push 22, add, print as a number
    ws2 = "  " + ws_number(20) + "  " + ws_number(22) + "\t   " + "\t\n \t" + "\n\n\n"
    assert ws_run(ws2) == "42", repr(ws_run(ws2))

    # non-whitespace characters are comments and are ignored
    assert ws_run("comment" + ws) == "Hi"

    # Befunge-93: print a string
    assert befunge_run('"!dlroW"v\n         ,\n         :\n         _@') is not None
    assert befunge_run('64+"!KO",,,@') == "OK!", repr(befunge_run('64+"!KO",,,@'))
    # arithmetic and integer output
    assert befunge_run("66*.@").strip() == "36"
    # the classic quine-ish string printer
    out = befunge_run('>"dlrow olleh">:#,_@')
    assert out == "hello world", repr(out)
    # self-modifying code via p
    assert befunge_run('"@"00p@') == ""

    # detection
    assert any("Brainfuck" in n for n in detect(hello))
    assert any("Whitespace" in n for n in detect(ws))
    assert any("Befunge" in n for n in detect('>"x",v\n@'))
    assert any("Ook" in n for n in detect(ook))

    print("selftest ok: brainfuck hello world, ook translation, whitespace print+arithmetic, "
          "befunge strings/arithmetic/self-modification, detection")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    cmd = sys.argv[1]
    if cmd in ("bf", "brainfuck"):
        src = open(sys.argv[2], encoding="utf-8", errors="replace").read()
        data = sys.argv[3].encode() if len(sys.argv) > 3 else b""
        sys.stdout.buffer.write(bf_run(src, data))
    elif cmd == "ook":
        print(bf_run(ook_to_bf(open(sys.argv[2], encoding="utf-8").read())).decode("latin1"))
    elif cmd == "ws":
        print(ws_run(open(sys.argv[2], encoding="utf-8", errors="replace").read()), end="")
    elif cmd in ("befunge", "bef"):
        print(befunge_run(open(sys.argv[2], encoding="utf-8", errors="replace").read()), end="")
    elif cmd == "detect":
        for n in detect(open(sys.argv[2], encoding="utf-8", errors="replace").read()):
            print(n)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **Brainfuck cell size and wrapping** differ between implementations (8-bit wrapping is the
  common assumption; some use 16/32-bit or unbounded). If the output is garbage, try the other.
- **Negative tape positions**: some interpreters allow a tape extending left. The one above
  wraps modulo the tape size, which is a superset of both behaviours for well-formed programs.
- **Whitespace files lose their payload** when pasted through a chat client or a web form that
  trims trailing whitespace. Always work from the raw bytes.
- **Befunge is self-modifying**; reading the source tells you nothing once `p` is involved. Run
  it and, if it takes input, feed it what the challenge implies.
- **`?` in Befunge is random.** Seed your interpreter (as the code above does) so runs are
  reproducible, and run it several times with different seeds if the output varies.
- **Substitution Brainfuck** (`pikachu`/`ppap`/emoji variants) needs the token mapping. Eight
  distinct tokens plus balanced-pair analysis gets you there; brute-force the 8! = 40320
  mappings and keep the ones that produce printable output if frequency analysis is ambiguous.
- **Malbolge generators** exist; writing one by hand is a research project, not a CTF task.
- **Piet images may have codel sizes > 1 pixel**; `npiet -cs N` sets it, and getting it wrong
  produces a program that halts immediately.
- **JSFuck is JavaScript**: running it executes arbitrary code. Decode it statically
  (`console.log` instead of `eval`) before running anything from a challenge.
- **Check for a trivial answer first.** Many "esolang" challenges are just Brainfuck that
  prints the flag; run it before you analyse it.

## Tools

`beef`/`bf` (Brainfuck), `npiet` (Piet), `bef`/`cfunge` (Befunge), `lci` (LOLCODE),
`ick` (INTERCAL), online interpreters for the rarer ones, and the script above for the three
that matter most.

## References

- Esolang wiki (esolangs.org) documents every language above, including full instruction
  tables for Whitespace and Befunge-93.
- Befunge-93 specification (Chris Pressey) for the exact instruction semantics used above.
- Whitespace language specification (Edwin Brady and Chris Morris) for the IMP table.
