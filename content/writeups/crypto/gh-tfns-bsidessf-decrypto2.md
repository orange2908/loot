---
title: "decrypto2 - BSidesSF 2020"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "xor", "decrypto2", "cryptography", "bsidessf", "tfns"]
summary: "In the challenge we get an encryption algorithm and encrypted svg."
source:
  name: "TFNS/writeups"
  url: "https://github.com/TFNS/writeups/blob/036f5f7d06a0ea5509de12699ba6993f5f37b8e6/2020-02-23-BSidesSF/decrypto2/README.md"
ctf:
  name: "BSidesSF"
  year: 2020
  challenge: "decrypto2"
---

## Source

- **CTF:** BSidesSF 2020
- **Challenge:** decrypto2
- **Repository:** [TFNS/writeups](https://github.com/TFNS/writeups)
- **File:** <https://github.com/TFNS/writeups/blob/036f5f7d06a0ea5509de12699ba6993f5f37b8e6/2020-02-23-BSidesSF/decrypto2/README.md>

---
# Decrypto-2 (crypto, 65p, 26 solved)

In the challenge we get an [encryption algorithm](https://raw.githubusercontent.com/TFNS/writeups/036f5f7d06a0ea5509de12699ba6993f5f37b8e6/2020-02-23-BSidesSF/decrypto2/decrypto.py) and [encrypted svg](https://raw.githubusercontent.com/TFNS/writeups/036f5f7d06a0ea5509de12699ba6993f5f37b8e6/2020-02-23-BSidesSF/decrypto2/flag.svg.enc).

The algorithm is a simple stream cipher.
The keystream is generated using:

```python
    def __init__(self, key):
        super(HashCrypto, self).__init__(key)
        self._blk = self.key
        self._blkid = 0

    def _extend_buf(self):
        self._blk = hashlib.sha256(
            self._blk + struct.pack('<I', self._blkid)).digest()
        self._blkid += 1
        self._buf += self._blk
```

Keystream block comes from sha256 hashing of previously generated keystream block plus block counter, with secret `key` as IV.
Since the next block depends only on the previous block (and first block on `key`) it's clear we could technically `start` keystream generation from any block, assuming we know the previous block and we know the number of the block.

The key observatin is that we don't need to start from the `key` - we can just as well start generating keystream from second block.
For this we need to know the first keystream block, but since it's a stream cipher, the ciphertext is `plaintext XOR keystream`.
If we can guess the first block of plaintext, we can use XOR to recover the keystream for first block.

We know that the input is SVG file, so we tested out all possible SVG file prefixes we could find and finally we managed to get the right one: `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`

Once we have that it's trivial to recover the flag:

```python
data = open("flag.svg.enc", 'rb').read()
prefix = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
keystream = xor_string(data, prefix[:32])
crypter = HashCrypto(keystream)
# move keystream generation one block further
crypter._blkid = 1
crypter._blk = keystream
crypter._buf = keystream
open("out.svg", 'wb').write(''.join(crypter.encrypt(data)))
```

And we get `CTF{but_even_I_couldnt_break_IT}`
