---
title: "numerology - Google Capture The Flag 2025"
category: "crypto"
subcategory: "stream-cipher"
type: "writeup"
tags: ["steam", "crypto", "chacha20", "numerology", "stream-cipher", "google-capture-the-flag", "google-capture-the-flag-2025", "2025", "ctf-writeup"]
summary: "crypto-numerology (Crypto, 50 pts)"
source:
  name: "CTFtime writeup #40328"
  url: "https://ctftime.org/writeup/40328"
original_source: "https://github.com/CTF-STeam/ctf-writeups/tree/master/2025/GoogleCTF/crypto-numerology"
ctf:
  name: "Google Capture The Flag 2025"
  year: 2025
  challenge: "numerology"
---

## Metadata

- **CTF:** Google Capture The Flag 2025
- **Task:** numerology
- **Author team:** STeam
- **CTFtime tags:** steam, crypto
- **CTFtime:** <https://ctftime.org/writeup/40328>
- **Original writeup:** <https://github.com/CTF-STeam/ctf-writeups/tree/master/2025/GoogleCTF/crypto-numerology>

---
**crypto-numerology (Crypto, 50 pts)**

This challenge presents a custom stream cipher inspired by ChaCha20 - but with a twist: it uses only a single round of mixing operations.

Given a known key and a batch of plaintext/ciphertext pairs, the task is to decrypt a secret message.

By analyzing the known samples, we recovered the keystream and brute-forced the correct counter value using a fixed nonce. A great exercise in exploiting weakened cipher designs.

**Flag:** `CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}` 

See the [full writeup](<https://github.com/CTF-STeam/ctf-writeups/tree/master/2025/GoogleCTF/crypto-numerology>) for detailed analysis and solution.
