---
title: "wandering - TRX CTF 2026"
category: "rev"
subcategory: "image"
type: "writeup"
tags: ["rev", "pie", "lsb", "wandering", "image", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "compose.yaml Dockerfile flag.txt run.sh vm"
source:
  name: "CTFtime writeup #40714"
  url: "https://ctftime.org/writeup/40714"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-wandering-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "wandering"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** wandering
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40714>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-wandering-writeup>

---
1\. Recon

$ ls  
compose.yaml Dockerfile flag.txt [run.sh](http://run.sh) vm  
$ file vm  
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped  
The Dockerfile wires a socat -T 60 TCP-LISTEN:1337,reuseaddr,fork EXEC:/app/[run.sh](http://run.sh) to a shell that loops the VM forever:

while true; do "$VM_BIN" || true; done  
So a single TCP connection can run many VM instances back-to-back — each starts fresh, with a new seed.

Useful strings recovered from the binary:

%d%c%d  
/flag.txt  
incorrect!  
correct!  
Failed initialization  
%d%c%d immediately tells us input is <int><char><int> per record.

The repeating pattern 22 49 40 22 ... in .data (visible as "I@" in the hex dump) is suspicious — it hints at a fixed bytecode table where many instructions share a leading dword.
