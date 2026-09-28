---
title: "Key Exchange - N0PSctf"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "cryptography", "aes", "key", "exchange", "n0psctf", "ctf-writeup"]
summary: "Challenge Name: Key Exchange"
source:
  name: "CTFtime writeup #40264"
  url: "https://ctftime.org/writeup/40264"
ctf:
  name: "N0PSctf"
  challenge: "Key Exchange"
---

## Metadata

- **CTF:** N0PSctf
- **Task:** Key Exchange
- **Author team:** N0C715
- **CTFtime tags:** cryptography
- **CTFtime:** <https://ctftime.org/writeup/40264>

---
# N0PS CTF 2025 - Key Exchange Writeup

**Category**: CrypTopia   
**Challenge Name**: Key Exchange   
**Flag**: ✅ `N0PS{d1fFi3_h31lm4n_k3y_XcH4ng3}`   
**Author**: algorab

\---

## Challenge Description

We’re given a connection endpoint to a secret service belonging to CrypTopia:

```  
nc [0.cloud.chals.io](http://0.cloud.chals.io) 26625  
```

The challenge implies that if we manage to speak the right language to this service, it will reward us with the flag. The format is `N0PS{...}`. No additional hints — just the address and an attached Python script.

\---

Naturally, I started by connecting to the server using netcat to see what kind of response it gives:

```  
nc [0.cloud.chals.io](http://0.cloud.chals.io) 26625  
```

As expected, I was greeted with a screen full of binary garbage. This was a clear sign that the server is expecting a binary-level protocol, not plain text.

![nc binary dump](<https://i.ibb.co/5Xkfm7zQ/Screenshot-from-2025-06-02-13-03-09.png>)

. The file was named `[main.py](http://main.py)` given , and it contained the core logic running on the server.   
\---

## Code Breakdown

The script performs a Diffie-Hellman key exchange followed by AES encryption of a flag file. Here's a brief summary:

\- The server generates a safe prime `p` and a generator `g`.  
\- It calculates `k_a = g^a mod p` where `a` is a random private key.  
\- It sends `p`, `g`, and `k_a` to the client.  
\- The client is expected to respond with `k_b = g^b mod p`.  
\- Both parties compute the shared secret key `k = g^(ab) mod p`.  
\- The server uses `SHA-256(k)` as an AES key to encrypt the flag and send it back.

\---

## Realization

What we had here was a textbook example of a **Diffie-Hellman key exchange** implemented in a CTF setting. The goal is to mirror the server’s steps, perform the math on our side, and decrypt the flag ourselves.

To solve it, I needed to:

1\. Parse the 1024-byte `p`, `g`, and `k_a` values sent by the server.  
2\. Generate a private `b`, compute `k_b`, and send it back.  
3\. Receive the AES-encrypted flag.  
4\. Derive the same shared key and decrypt the ciphertext.

\---

## Building the Exploit Script

To automate this, I wrote a Python script using `socket`, `Crypto`, and `hashlib` libraries. One important note: the server sends 1024 **bytes**, not bits — I initially messed this up and got all zeroes for `p`, `g`, and `k_a`.

Once that was corrected, everything lined up.

![solver script](<https://i.ibb.co/v4BWGRHf/Screenshot-from-2025-06-02-13-07-54.png>)

\---

## Decryption & Discovery

After decryption, the data didn't look like text, so I ran:

```  
file decrypted_flag.bin  
```

And saw this:

```  
PNG image data, 4267 x 4267, 8-bit/color RGBA  
```

\---  
converted it to the png file 

```  
mv decrypted_flag.bin flag.png

```

Bingo. The flag was embedded inside an image.

`decrypted_flag.bin: PNG image data, 4267 x 4267, 8-bit/color RGBA`

I opened the file and found the flag painted on top of a shiny treasure chest.

![flag image](<https://i.ibb.co/C3vLchMj/flag.png>)

\---

## ? Final Flag

```  
N0PS{d1fFi3_h31lm4n_k3y_XcH4ng3}  
```

\---  
Team N0C71S
