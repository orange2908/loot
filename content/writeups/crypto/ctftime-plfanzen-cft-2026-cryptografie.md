---
title: "Cryptografie - plfanzen CFT 2026"
category: "crypto"
type: "writeup"
tags: ["crypto", "cryptografie", "plfanzen-cft", "plfanzen-cft-2026", "2026", "ctf-writeup"]
summary: "The approach involved reading the FileSystemPreferences.java source code to pinpoint the dirName (encoder) and nodeName (decoder) methods."
source:
  name: "CTFtime writeup #40814"
  url: "https://ctftime.org/writeup/40814"
original_source: "https://github.com/n4ctbyte/ctf-writeups/blob/main/plfanzen-ctf-2026/cryptografie.md"
ctf:
  name: "plfanzen CFT 2026"
  year: 2026
  challenge: "Cryptografie"
---

## Metadata

- **CTF:** plfanzen CFT 2026
- **Task:** Cryptografie
- **Author team:** TCP1P
- **CTFtime:** <https://ctftime.org/writeup/40814>
- **Original writeup:** <https://github.com/n4ctbyte/ctf-writeups/blob/main/plfanzen-ctf-2026/cryptografie.md>

---
The approach involved reading the `FileSystemPreferences.java` source code to pinpoint the `dirName` (encoder) and `nodeName` (decoder) methods. Since `nodeName` is a `private` method, I wrote a custom Java script utilizing `java.lang.reflect.Method` to forcefully invoke it on the ciphertext. Finally, I bypassed modern Java module security constraints using JVM execution flags to allow the reflection to succeed.
