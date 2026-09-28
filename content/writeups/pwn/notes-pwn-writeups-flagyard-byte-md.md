---
title: "Byte (Flagyard)"
category: "pwn"
subcategory: "writeups"
type: "writeup"
tags: ["my-notes", "personal", "canary", "pie", "checksec", "pwn"]
summary: "Personal note: Byte (Flagyard)."
source:
  name: "Personal notes"
origin_path: "pwn/Writeups/Flagyard/Byte.md"
---

```bash
➜  byte checksec byte
[*] '/home/serioton/ctf/flagyard/pwn/byte/byte'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

```c

/* WARNING: Function: __x86.get_pc_thunk.ax replaced with injection: get_pc_thunk_ax */

undefined4 main(void)

{
  setup();
  vuln();
  return 0;
}
```

```c

/* WARNING: Function: __x86.get_pc_thunk.ax replaced with injection: get_pc_thunk_ax */

void vuln(void)

{
  undefined1 buffer [132];
  
  read(0,buffer,137);
  return;
}
```

```c

/* WARNING: Function: __x86.get_pc_thunk.ax replaced with injection: get_pc_thunk_ax */

void win(void)

{
  system("/bin/sh");
  return;
}
```

```

```

---

*From your own notes: `pwn/Writeups/Flagyard/Byte.md`*
