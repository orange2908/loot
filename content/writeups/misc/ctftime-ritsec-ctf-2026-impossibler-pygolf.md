---
title: "impossibler pygolf - RITSEC CTF 2026"
category: "misc"
type: "writeup"
tags: ["misc", "os-system", "symlink", "impossibler", "pygolf", "ritsec-ctf", "ritsec-ctf-2026", "2026", "ctf-writeup"]
summary: "A MicroPython code golf challenge: submit hex-encoded code (score = hex length, max 103) that prints the first stanza of the Jabberwocky."
source:
  name: "CTFtime writeup #40779"
  url: "https://ctftime.org/writeup/40779"
ctf:
  name: "RITSEC CTF 2026"
  year: 2026
  challenge: "impossibler pygolf"
---

## Metadata

- **CTF:** RITSEC CTF 2026
- **Task:** impossibler pygolf
- **Author team:** wombatwarfare
- **CTFtime:** <https://ctftime.org/writeup/40779>

---
A MicroPython code golf challenge: submit hex-encoded code (score = hex length, max 103) that prints the first stanza of the Jabberwocky. The text lives inside `libmbedcrypto.so.16` as an mbedTLS test vector; `grep -z` extracts it and `xargs -0` strips the trailing null in exactly 51 bytes of code.

## Solution

### Step 1: Understand the constraints

Connect and poke at the service. It takes hex, decodes it to MicroPython code, execs it, and compares stdout to the Jabberwocky poem. The score is `len(hex_input)` and must be ≤ 103. Since `bytes.fromhex` needs even-length input, that's 102 hex chars = 51 bytes of code. We need 51 bytes of MicroPython to print 127 bytes of specific text.

Quick math rules out embedding or compressing the text — 127 bytes of entropy can't fit in 51 bytes of code plus decoder. The data has to come from somewhere on the filesystem.

### Step 2: Find the text

`sys` is pre-imported in the exec namespace, `os.system` works after `import os`, so we can run shell commands. Searching for the Jabberwocky's most distinctive word:

```python  
import os;os.system('grep -rl brillig /usr /lib 2>/dev/null')  
```

```  
/lib/x86_64-linux-gnu/libmbedcrypto.so.3.6.5  
```

The Jabberwocky stanza is a well-known test vector in mbedTLS (used for ARIA cipher tests). The library is already loaded by MicroPython at startup, and a shorter soname symlink `libmbedcrypto.so.16` exists. The glob `/*/*/*16` uniquely matches it at three directory levels deep.

### Step 3: Extract it

The text sits as a null-terminated C string in the `.rodata` section. `grep -z` treats null bytes as line separators instead of newlines, so the entire 127-byte poem (which contains internal newlines) becomes one "line" bounded by nulls on both sides. The problem is that `grep -z` also terminates its output with a null byte, which poisons the string comparison in the outer checker.

The breakthrough: `xargs -0` reads null-delimited input and, with no command specified, defaults to `echo`. This strips the trailing null and outputs the clean text with a trailing newline that `.strip()` removes. The pipe `|xargs -0` is exactly 9 characters — compact enough to fit the budget.

```  
grep -z Tw /*/*/*16|xargs -0  
```

28 characters of shell command + 23 bytes of `import os;os.system('...')` = 51 bytes = 102 hex chars. Score 102 ≤ 103.

### Solve script

```python  
#!/usr/bin/env python3  
"""Solve 'impossibler pygolf' — RITSEC CTF 2026 (Misc)"""  
from pwn import *

code = b"import os;os.system('grep -z Tw /*/*/*16|xargs -0')"  
print(f"[*] {len(code)}b = {len(code.hex())} hex chars")

r = remote("impossibler-pygolf.ctf.ritsec.club", 1234)  
r.recvuntil(b"hex > ")  
r.sendline(code.hex().encode())  
print(r.recvall(timeout=15).decode())  
```

```  
$ python3 [solve.py](http://solve.py)  
[*] 51b = 102 hex chars  
got:  
"""  
'Twas brillig, and the slithy toves  
Did gyre and gimble in the wabe:  
All mimsy were the borogoves,  
And the mome raths outgrabe.  
"""

RS{s0rry_i_kn0w_th4t_w4s_stup1d_bu7_i_th0ugh7_i7_w4s_4_b1t_funny_102_b1b34d90}
