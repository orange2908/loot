---
title: "The Onion - CTF@CIT 2026"
category: "crypto"
type: "writeup"
tags: ["crypto", "hashcat", "base64", "onion", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Value: 798 pts (203 solves)"
source:
  name: "CTFtime writeup #40728"
  url: "https://ctftime.org/writeup/40728"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "The Onion"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** The Onion
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40728>

---
# The Onion — Writeup

\- Category: Crypto  
\- Value: 798 pts (203 solves)  
\- Author: elemental

## Challenge

`challenge.txt` contains a single long ASCII blob that starts with `Vm0wd2QyUXlVWGxWV0d4V...`. The description invites us to "peel back the layers". The `SHA1: 6ca8b4ae8d7317b27f564bc962a20b3e6fb49c72` listed on the challenge is the SHA1 of the stripped file content (file-integrity marker), not of the flag:

```text  
$ tr -d '\n' < files/challenge.txt | shasum -a 1  
6ca8b4ae8d7317b27f564bc962a20b3e6fb49c72  
```

## Recon

The blob is a Base64 onion, but the trick is knowing **when to stop** — and then knowing **what kind of hash** you're looking at.

## Solve

1\. Iteratively Base64-decode. After **15** decodes the payload is `b9486c74c779db5194d6508bebbee72b\n` (32-char lowercase hex). One more Base64 decode yields 24 bytes of noise, so stop here.  
2\. The 32-hex string is a hash. `MD5(flag)` does not produce it, but `NTLM(flag) = MD4(flag.encode("utf-16le"))` does. That's the "unused information" — the hash type.  
3\. Crack it with hashcat mode 1000 against `rockyou.txt`:

```bash  
echo b9486c74c779db5194d6508bebbee72b > /tmp/ntlm.txt  
hashcat -m 1000 -a 0 /tmp/ntlm.txt /tmp/rockyou.txt  
# b9486c74c779db5194d6508bebbee72b:iloveharrypottersomuchthaticouldreadallthebooksintwodaysmostlikely  
```

(~6 seconds on an M-series CPU — NTLM is deliberately fast.)

The vendored `files/challenge.txt` is **2616** bytes (no trailing newline after `==`).

## Flag

```text  
CIT{iloveharrypottersomuchthaticouldreadallthebooksintwodaysmostlikely}  
```

## Files

\- [files/challenge.txt](files/challenge.txt) — original Base64-stacked ciphertext  
\- [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py)) — peel to the inner NTLM hash, then verify the recovered plaintext locally  
\- [solution/flag.txt](solution/flag.txt) — recorded submission
