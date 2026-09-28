---
title: "restricted oracle - GPN CTF 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "cbc", "xor", "restricted", "oracle", "gpn-ctf", "gpn-ctf-2025", "2025", "ctf-writeup"]
summary: "The source code is a Python script chall.py that uses AES.MODECBC to decrypt user inputs."
source:
  name: "CTFtime writeup #40336"
  url: "https://ctftime.org/writeup/40336"
original_source: "https://lape.si/writeups/gpn23/restrictedoracle"
ctf:
  name: "GPN CTF 2025"
  year: 2025
  challenge: "restricted oracle"
---

## Metadata

- **CTF:** GPN CTF 2025
- **Task:** restricted oracle
- **Author team:** Platypwnies
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/40336>
- **Original writeup:** <https://lape.si/writeups/gpn23/restrictedoracle>

---
The source code is a Python script `[chall.py](http://chall.py)` that uses `AES.MODE_CBC` to decrypt user inputs. But instead of returning the decrypted data, it returns if the padding is correct or not. This allows us to reverse the internal state of the decryption process and ultimately recovering the plaintext.

When connecting to the server we get two hex strings, the first one will be useful later, the second one is a encrypted text containing random german words. We need to decrypt this text to get the flag later.

The attack we are going to use is explained [here](<https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/>) in great detail with animations and code.

Essentially, we will use the fact that the server tells us if the padding is correct or not to iteratively guess the plaintext byte by byte. We will start with the last byte and work our way to the first byte. This works because the padding is only valid if the `n` padding bytes at the end of the plaintext are all equal to `n`. For example, if there are 3 padding bytes, the last 3 bytes of the plaintext must be `0x03 0x03 0x03`.

This lets us recover the internal state of the decryption process, which we can then `xor` with the initialization vector (IV) to get the plaintext. For a more intuitve understanding, check the animations mentioned above.

For more see the full writeup:  
[<https://lape.si/writeups/gpn23/restrictedoracle>](<https://lape.si/writeups/gpn23/restrictedoracle>)
