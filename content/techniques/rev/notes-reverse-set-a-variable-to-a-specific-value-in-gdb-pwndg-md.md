---
title: "Set a variable to a specific value in gdb-pwndg (Reverse)"
category: "rev"
type: "technique"
tags: ["my-notes", "personal", "pwndbg", "set", "variable", "specific", "value", "gdb-pwndg", "rev", "reverse"]
summary: "Personal note: Set a variable to a specific value in gdb-pwndg (Reverse)."
source:
  name: "Personal notes"
origin_path: "Reverse/Set a variable to a specific value in gdb-pwndg.md"
---

```bash
pwndbg> break *main+278
```

```bash
pwndbg> r
```

```bash
pwndbg> set {int}($rbp-0x4)=5
```

```bash
pwndbg> c
Continuing.
Nice!

DH{389998e56e90e8eb34238948469cecd6dd89c04dce359c345e0b2f3ef9edc66a}
```

- Reference: https://dreamhack.io/wargame/challenges/851

---

*From your own notes: `Reverse/Set a variable to a specific value in gdb-pwndg.md`*
