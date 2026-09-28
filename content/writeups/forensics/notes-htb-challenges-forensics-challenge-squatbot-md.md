---
title: "Challenge - SquatBot (Forensics)"
category: "forensics"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "volatility", "squatbot", "forensics", "htb-challenges"]
summary: "So what is a file descriptor?"
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Forensics/Challenge - SquatBot.md"
---

### **File Descriptor**

So what is a file descriptor? A file descriptor is unique for each process integer identifier which acts as a handle to I/O operations. Every process has its set of file descriptors. The most common are:

- stdin: Standard Input, its file descriptor id is 0.
- stdout: Standard Output, its file descriptor id is 1.
- stderr: Standard Error, its file descriptor id is 2.

### enumerate the open file descriptors of each process in volatility

```bash
linux_lsof -p $pid
```

```
https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/linux/lsof.py\#L44
```

### **linux_volshell**

By using **linux_volshell** we have an interactive python shell in a specific process's memory space.

```python
from volatility.renderers.basic import Address

task = self._proc

for flip, fd in task.lsof():

  print(0,[Address(task.obj_offset),str(task.comm),int(task.pid),int(fd),filp])
	if fd ==4:
			addr = str(flip)
			dt('file',addr)
```

### Extract a file knowing its inode

```bash
linux_find_file -i $inode -O $output
```

### Writeup

```
https://www.hackthebox.com/blog/squatbot-biz-ctf-2022-forensics-writeup
```

---

*From your own notes: `HTB Challenges/Forensics/Challenge - SquatBot.md`*
