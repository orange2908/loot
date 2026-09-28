---
title: "Brain - n00bzCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "brain", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "We are presented a string in brainfuck language."
source:
  name: "CTFtime writeup #39378"
  url: "https://ctftime.org/writeup/39378"
original_source: "https://moormaster.github.io/CtfWriteups/brain.html"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Brain"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Brain
- **Author team:** zwiebel
- **CTFtime:** <https://ctftime.org/writeup/39378>
- **Original writeup:** <https://moormaster.github.io/CtfWriteups/brain.html>

---
We are presented a string in [brainfuck](https://en.wikipedia.org/wiki/Brainfuck) language. The first thing we notice that it is not outputting anything (not a single '.' character in it).

```
    >+++++++++++[<++++++++++>-]<[-]>++++++++[<++++++>-]<[-]>++++++++[<++++++>-]<[-]
    >++++++++++++++[<+++++++>-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<++>-]<[-]
    >+++++++++++++++++++++++++++++++++++++++++[<+++>-]<[-]>+++++++[<+++++++>-]<[-]
    >+++++++++++++++++++[<+++++>-]<[-]>+++++++++++[<+++++++++>-]<[-]>+++++++++++++[<++++>-]<[-]
    >+++++++++++[<++++++++++>-]<[-]>+++++++++++++++++++[<+++++>-]<[-]>+++++++++++[<+++++++++>-]<[-]
    >++++++++[<++++++>-]<[-]>++++++++++[<++++++++++>-]<[-]>+++++++++++++++++[<+++>-]<[-]
    >+++++++++++++++++++[<+++++>-]<[-]>+++++++[<+++++++>-]<[-]>+++++++++++[<++++++++++>-]<[-]
    >+++++++++++++++++++[<+++++>-]<[-]>++++++++++++++[<+++++++>-]<[-]
    >+++++++++++++++++++[<++++++>-]<[-]>+++++++++++++[<++++>-]<[-]>+++++++[<+++++++>-]<[-]
    >+++++++++++[<++++++++++>-]<[-]>+++++++++++++++++[<++++++>-]<[-]>+++++++[<++++++>-]<[-]
    >+++++++++++[<+++++++++>-]<[-]
    >+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-]<[-]
    >+++++++++++[<+++>-]<[-]>+++++++++++++++++++++++++[<+++++>-]<[-]
```

The next thing that jumps into ones eye are these `<[-]`. The `<` jumps right back into the previous memory cell while `[-]` is equal to

```
    while (cell_value[i] != 0) {
        cell_value[i]--;
    }
```

and causes whatever value was written into that cell before to be decreased to 0 again.

Since we are curious we want to output each of these values before they get neutralized again. So our task here is to simply insert a `.` command into each of the `<[-]` commands: `<.[-]`

Putting the resulting `brainfuck` code into a brainfuck interpreter will now give us the flag.
