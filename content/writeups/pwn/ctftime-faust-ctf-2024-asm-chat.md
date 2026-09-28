---
title: "asm_chat - FAUST CTF 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "musl", "formatstring", "bufferoverflow", "binary", "sessions", "buffer-overflow", "format-string", "stack", "faust-ctf", "faust-ctf-2024", "2024", "ctf-writeup"]
summary: "achat (or asmchat in the scoreboard) is a binary generated from C source code, which was a service from FaustCTF 2024."
source:
  name: "CTFtime writeup #39483"
  url: "https://ctftime.org/writeup/39483"
original_source: "https://saarsec.rocks/2024/09/29/FAUSTCTF-achat.html"
ctf:
  name: "FAUST CTF 2024"
  year: 2024
  challenge: "asm_chat"
---

## Metadata

- **CTF:** FAUST CTF 2024
- **Task:** asm_chat
- **Author team:** saarsec
- **CTFtime tags:** c, musl, formatstring, bufferoverflow, binary, c, sessions
- **CTFtime:** <https://ctftime.org/writeup/39483>
- **Original writeup:** <https://saarsec.rocks/2024/09/29/FAUSTCTF-achat.html>

---
achat (or asm_chat in the scoreboard) is a binary generated from C source code, which was a service from FaustCTF 2024. It features a simple chat system, where users can create chats with each other and send text messages. It has two vulnerabilities, of which only one is actually exploitable: a too lazy session check, and a combined buffer overflow/format string.

In short:  
```  
$ list-users 123...45  
\- checkKLPPQlYmgyKUwPuY  
$ search heckKLPPQlYmgyKUwPuY FAUST  
... flags ...  
```

The (non-exploitable format string):  
```  
$ send 12...34 x&y AAA...AAA%p%p...%p%p  
$ search AAAAA  
0x729f933c9ce0  
0x5a1ada9bc643  
...  
```
