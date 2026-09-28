---
title: "Iced TEA - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
type: "writeup"
tags: ["crypto", "ecb", "cbc", "xor", "iced", "tea", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "We are given the Python source code that encrypts the flag:"
source:
  name: "CTFtime writeup #39005"
  url: "https://ctftime.org/writeup/39005"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/iced-tea/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Iced TEA"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Iced TEA
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/39005>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/iced-tea/>

---
We are given the Python source code that encrypts the flag:

`

```
    import os
    from secret import FLAG
    from Crypto.Util.Padding import pad
    from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
    from enum import Enum
    
    class Mode(Enum):
        ECB = 0x01
        CBC = 0x02
    
    class Cipher:
        def __init__(self, key, iv=None):
            self.BLOCK_SIZE = 64
            self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
            self.DELTA = 0x9e3779b9
            self.IV = iv
            if self.IV:
                self.mode = Mode.CBC
            else:
                self.mode = Mode.ECB
        
        def _xor(self, a, b):
            return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))
    
        def encrypt(self, msg):
            msg = pad(msg, self.BLOCK_SIZE//8)
            blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
            
            ct = b''
            if self.mode == Mode.ECB:
                for pt in blocks:
                    ct += self.encrypt_block(pt)
            elif self.mode == Mode.CBC:
                X = self.IV
                for pt in blocks:
                    enc_block = self.encrypt_block(self._xor(X, pt))
                    ct += enc_block
                    X = enc_block
            return ct
    
        def encrypt_block(self, msg):
            m0 = b2l(msg[:4])
            m1 = b2l(msg[4:])
            K = self.KEY
            msk = (1 << (self.BLOCK_SIZE//2)) - 1
    
            s = 0
            for i in range(32):
                s += self.DELTA
                m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
                m0 &= msk
                m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
                m1 &= msk
            
            m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1
    
            return l2b(m)
    
    
    
    if __name__ == '__main__':
        KEY = os.urandom(16)
        cipher = Cipher(KEY)
        ct = cipher.encrypt(FLAG)
        with open('output.txt', 'w') as f:
            f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
```

`

We also have the output of the script:

`

```
    Key : 850c1413787c389e0b34437a6828a1b2
    Ciphertext : b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843
```

`

## Source code analysis

The server uses a `Cipher` class to encrypt the flag. The server does not explicitly tell what encryption algorithm is using, but it is fairly easy to see that it is [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) (TEA), which is a symmetric block cipher.

Notice that we are given the encryption key and the ciphertext, so we only need to decrypt it. However, the `Cipher` class does not implement `decrypt` and `decrypt_block` functions, so we will need to implement them.

## Decryption

The decrytion functions are easy to implement, we only need to do the inverse operations of `encrypt` and `encrypt_block` in reverse order. Otherwise, we can take a look at [Wikipedia](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) and translate the reference code in C to Python.

Anyways, these are the necessary functions:

`

```
        def decrypt(self, msg_ct):
            blocks = [msg_ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg_ct), self.BLOCK_SIZE//8)]
            
            pt = b''
            if self.mode == Mode.ECB:
                for ct in blocks:
                    pt += self.decrypt_block(ct)
            elif self.mode == Mode.CBC:
                X = self.IV
                for ct in blocks:
                    dec_block = self._xor(X, self.decrypt_block(ct))
                    pt += dec_block
                    X = ct
            return unpad(pt, self.BLOCK_SIZE//8)
    
        def decrypt_block(self, m):
            m0 = b2l(m[:4])
            m1 = b2l(m[4:])
            K = self.KEY
            msk = 0xffffffff
    
            s = 32 * self.DELTA
    
            for _ in range(32):
                m1 -= (((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3]))
                m1 &= msk
                m0 -= (((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1]))
                m0 &= msk
                s -= self.DELTA
    
            msg = ((m0 << 32) + m1) & 0xffffffffffffffff # m = m0 || m1
    
            return l2b(msg)
```

`

At this point, we can take the encryption key and the ciphertext from `output.txt` and decrypt the flag:

`

```
    KEY = bytes.fromhex('850c1413787c389e0b34437a6828a1b2')
    ct = bytes.fromhex('b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843')
    
    print(Cipher(KEY).decrypt(ct).decode())
```

`

## Flag

And here’s the flag:

`

```
    $ python3 solve.py
    HTB{th1s_1s_th3_t1ny_3ncryp710n_4lg0r1thm_____y0u_m1ght_h4v3_4lr34dy_s7umbl3d_up0n_1t_1f_y0u_d0_r3v3rs1ng}
```

`
