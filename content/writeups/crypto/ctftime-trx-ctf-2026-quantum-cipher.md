---
title: "quantum-cipher - TRX CTF 2026"
category: "crypto"
type: "writeup"
tags: ["crypto", "quantum-cipher", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "We're given a Python service that runs a custom \"quantum\" block cipher on 8-bit blocks using Qiskit:"
source:
  name: "CTFtime writeup #40719"
  url: "https://ctftime.org/writeup/40719"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-quantum-cipher-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "quantum-cipher"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** quantum-cipher
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40719>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-quantum-cipher-writeup>

---
Challenge  
We're given a Python service that runs a custom "quantum" block cipher on 8-bit blocks using Qiskit:

NQUBITS = 8 ROUNDS = 12 MAX_QUERIES = 1  
Each connection generates secret = urandom(13). Of those, secret[0..11] drive the encryption rounds and secret[12] chooses an output slice. The interface lets us:

Encrypt one (1) chosen byte (MAX_QUERIES = 1).  
Get the encrypted flag (no limit, but deterministic).  
Each call returns a slice of 256 complex amplitudes per 8-bit block of plaintext.

The encryption circuit uses 16 qubits: 8 data qubits + 8 "key" qubits initialized to secret[0]. Each round does:

python

add_key # CRY(π/15) gates from key qubits to data qubits  
permutation # iswap chain over data qubits (fixed)  
rxz # RZX(π/e) on 4 disjoint pairs (fixed)  
evolve_key # X gates flipping key register from secret[r] → secret[r+1]  
Output: Statevector[secret[12]*256 : secret[12]*256+256].
