---
title: "cryptography 1 - sekaictf 2023"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "cryptography", "cryptography-1", "sekaictf", "project-sekai-ctf", "sekaictf-2023"]
summary: "Player is expected to understand the graph encryption scheme by reading the given library files."
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/crypto/cryptography-1/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "cryptography 1"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** cryptography 1
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/crypto/cryptography-1/solution/README.md>

---
## Solution

Player is expected to understand the graph encryption scheme by reading the given library files. In particular, `DES` class is the underlying cryptographic primitive, where `GES` implements the graph encryption scheme.

With some research, player might be able to find this paper: [Efficient Graph Encryption Scheme for Shortest Path Queries](https://dl.acm.org/doi/pdf/10.1145/3433210.3453099). Figure 1 has the algorithm in pseudocode. The library code is implemented in exactly the same way as the paper.

I have added enough comments to guide the player. In fact, `utils` and `DES` code are not needed to solve this challenge.

We are asked to send back the shortest path query given the ciphertext and the initially generated key. Upon reading GES `search` function, we just need to reverse the steps to get the plaintext. The steps are (as listed in paper):

1. Parse key as `(key_SKE, key_DES)`
2. Set variable `m = []`
3. Parse ciphertext into blocks of 32, because when searching and encrypting, we use 32-byte blocks as each piece of ciphertext.
4. For each block `ct_i`, decrypt it using `utils.SymmetricDecrypt(key_SKE, ct_i)` to get `pt_i` and append to `m`.
5. Deduct shortest path from source to destination from final `m`.

The main difficulty comes from understanding the source code - there's nothing in DES to be cracked, nor any cryptographic vulnerabilities to be exploited. Simply decrypt the ciphertext :)

The challenge is definitely easier if you find the original paper, which is in fact useful for solving challenge 2.
