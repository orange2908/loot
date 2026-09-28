---
title: "Enumerate me - The Hacker Conclave"
category: "misc"
type: "writeup"
tags: ["misc", "base64", "enumerate", "the-hacker-conclave", "ctf-writeup"]
summary: "In the Discovery directory i found a tests.txt file."
source:
  name: "CTFtime writeup #39259"
  url: "https://ctftime.org/writeup/39259"
ctf:
  name: "The Hacker Conclave"
  challenge: "Enumerate me"
---

## Metadata

- **CTF:** The Hacker Conclave
- **Task:** Enumerate me
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39259>

---
In the Discovery directory i found a tests.txt file.

I used the Dirbuster tool to search for the correct path from the file i found.  
```  
dirb <http://ctf.thehackerconclave.es:20001/> tests.txt  
```

It found this page [<http://ctf.thehackerconclave.es:20001/prueba1>](<http://ctf.thehackerconclave.es:20001/prueba1>) that had the flag in base64 format.

Flag: `conclave{7f52fcea1237b66122bd091b75642371}`
