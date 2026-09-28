---
title: "Pwntools (pwn)"
category: "pwn"
type: "technique"
tags: ["my-notes", "personal", "pwntools", "pwn"]
summary: "-> https://docs.pwntools.com/en/stable/log.html"
source:
  name: "Personal notes"
origin_path: "pwn/pwntools.md"
---

# Logging
## success
-> https://docs.pwntools.com/en/stable/log.html
-> https://ir0nstone.gitbook.io/notes/misc/pwntools/logging_and_context
```bash
success(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}')
```

```
╰─ python wrapper.py
[+] Opening connection to 94.237.61.202 on port 54807: Done
[+] Flag --> HTB{b0f_tut0r14l5_4r3_g00d}
[*] Closed connection to 94.237.61.202 port 54807
```

---

*From your own notes: `pwn/pwntools.md`*
