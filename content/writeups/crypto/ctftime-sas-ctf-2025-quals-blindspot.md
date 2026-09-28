---
title: "Blindspot - SAS CTF 2025 Quals"
category: "crypto"
subcategory: "ecdsa"
type: "writeup"
tags: ["crypto", "ecdsa", "blindspot", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Blindspot - SASCTF 2025 Write-up"
source:
  name: "CTFtime writeup #40249"
  url: "https://ctftime.org/writeup/40249"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Blindspot"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Blindspot
- **Author team:** Tenesys
- **CTFtime:** <https://ctftime.org/writeup/40249>

---
Blindspot - SASCTF 2025 Write-up

My Solution Approach  
To solve this challenge, I focused on how the server handled its signing nonces. Here's the strategy I used:

1\. Initial Setup: I started by connecting to the server, sending a `RESET` command to ensure a clean slate, and then fetched the server's public key `Q`.

2\. Exploiting Nonce Handling:  
* I initiated a signing session with a `REQUEST` command. This gave me the server's `R_serv`, which is tied to a specific nonce `k_serv` that the server would reuse for the current connection.  
* Then, on the *same connection*, I sent two carefully crafted, distinct challenges (`c_1` and `c_2`) via the `CHALLENGE` command. This made the server sign both challenges using the same `k_serv` and its private key `d`, returning `s_1` and `s_2`.

3\. Recovering the Private Key: With `s_1`, `s_2`, `c_1`, and `c_2`, I could calculate the server's private key `d` using the formula: `d = (s_1 - s_2) * (c_1 - c_2)^(-1) mod p`.

4\. Forging Signatures for the Win: Once I had `d`, I forged three new, distinct signatures for messages of my choosing.

5\. Meeting the Flag Condition: I submitted these forged signatures using the `VERIFY` command. The server's `counter_sign` was only 2 (from my two `CHALLENGE` calls), but after my three successful verifications, `verified_messages` became 3. This satisfied the condition `verified_messages > counter_sign`, and the server then sent the flag.

Solver & Tools  
I automated this process using a Python script (`[solver.py](http://solver.py)`). For the cryptographic operations, the `ecdsa` library was used. During the analysis of the server code, identifying how `k` was linked to the connection state rather than individual signature operations was the key to the solution. I also used AI assistance to quickly confirm the algebraic steps for the key recovery after my initial code review.

Full solver and details available on GitHub: [My GitHub Repository](<https://github.com/Romm31/CTFWriteUp/tree/main/Capture%20The%20Flag/2025/SASCTF2025/blindspot>)
