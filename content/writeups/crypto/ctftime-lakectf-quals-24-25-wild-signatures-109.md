---
title: "wild-signatures 109 - LakeCTF Quals 24-25"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "signature", "eddsa", "sage", "ed25519", "wild-signatures", "ecc", "lakectf-quals-24", "lakectf-quals-24-25", "ctf-writeup"]
summary: "2024-12-09  2026-03-29  About 700 words  3 minutes"
source:
  name: "CTFtime writeup #39700"
  url: "https://ctftime.org/writeup/39700"
original_source: "https://sylvainpelissier.gitlab.io/posts/2024-12-09-lakectf-wild-signatures/"
ctf:
  name: "LakeCTF Quals 24-25"
  challenge: "wild-signatures 109"
---

## Metadata

- **CTF:** LakeCTF Quals 24-25
- **Task:** wild-signatures 109
- **Author team:** Soudure au beurre
- **CTFtime tags:** signature, eddsa
- **CTFtime:** <https://ctftime.org/writeup/39700>
- **Original writeup:** <https://sylvainpelissier.gitlab.io/posts/2024-12-09-lakectf-wild-signatures/>

---
# LakeCTF 2024 Quals - Wild-Signatures 

[__Sylvain](https://github.com/sylvainpelissier "Author")

 __2024-12-09  __2026-03-29  __About 700 words  __3 minutes

Contents __

_This is the solution of the “wild-signatures” challenge of[LakeCTF 2024 Quals](https://lakectf.epfl.ch/). The challenge has a unintended solution but the intended solution was to solve it using Ed25519 low order public keys._

### Details

Category: Crypto

Points: 109

### Description

Can you even sign? Help leo get the flag as soon as possible.

`nc chall.polygl0ts.ch 9001`

Download Links: [server.py](https://sylvainpelissier.gitlab.io/resources/2024/lakectf/wild-signatures/server.py) [compose.yml](https://sylvainpelissier.gitlab.io/posts/2024-12-09-lakectf-wild-signatures/resources/2024/lakectf/wild-signatures/compose.yml) [Dockerfile](https://sylvainpelissier.gitlab.io/resources/2024/lakectf/wild-signatures/Dockerfile)

### Solutions

The server generates four [Ed25519](https://ed25519.cr.yp.to/papers.html) signatures $(R,S)$ for known messages. The $S$ parts of the signatures are then given and the goal it to send the a public key verifying this signature. However, the server reads as many bytes as we give to it and overwrite the existing signature if more bytes are given but we must send a message with at least one byte and at most 64 bytes:

__________

```
     1
    2
    3
    4
    5
    6
    7
    8
    9
```

| 

```
                # first 64 bytes encode the public key
                if len(user_msg) > 64 or len(user_msg) == 0:
                    print("you're talking too much, or too little")
                    exit()
                
                to_verif = user_msg + sig[len(user_msg):]
    
                parse_and_vfy_sig(to_verif, msg)
                print("it's valid")
```  
  
---|---  
  
#### Unintended solution

Since the signature value together with the public key is reused and passed to the verification function, we could just send one arbitrary chosen byte to the server until by chance we matched the first byte of the expected public key and then the signature will verify:

__________

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
```

| 

```
    from pwn import *
    
    rsp = b'Invalid Ed25519 public key\n'
    r = r = remote("challs.polygl0ts.ch", 9001)
    while rsp == b'Invalid Ed25519 public key\n' or rsp == b'The signature is not authentic\n':
        r.close()
        r = remote("challs.polygl0ts.ch", 9001)
        print(r.recvuntil(b"\n"))
        print(r.recvuntil(b"\n"))
        r.send(b"88\n")
        rsp = r.recvuntil(b"\n")
        print(rsp)
    
    r.interactive()
```  
  
---|---  
  
__

Then we needed only to send the same bytes, `88` in our case to get the flag:

__________

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
```

| 

```
    [*] Closed connection to challs.polygl0ts.ch port 9001
    [+] Opening connection to challs.polygl0ts.ch on port 9001: Done
    b'if you really are leo, give me public keys that can verify these signatures\n'
    b'67043eef048ec3d83580a5ad23c536a920e14c700aa1c3da8ec59d5dfecb8106\n'
    b"it's valid\n"
    [*] Switching to interactive mode
    94925a8f9dc6e62a4cf63cbd4855dbf0553b75482829de39c24ca01625d8360c
    $ 88
    it's valid
    ef270b1331acd9db6f6f45a4dc2cdfb40bc84f16bca190c8afe6258c8cb08000
    $ 88
    it's valid
    f2afc6e992180094083e3a252a67f50eae25a91c8fa17068b0283ce9d11ac100
    $ 88
    it's valid
    EPFL{wH4T_d0_yOu_m34n_4_W1LdC4Rd}
    [*] Got EOF while reading in interactive
```  
  
---|---  
  
 __

#### Intented solution

However, there was a more interesting solution. Each signature has the form $(R,S)$ and the verification check that the equation:

$$8 S \cdot B = 8 \cdot R + 8H(R,A,M) \cdot A$$

holds for a public key $A$ and the generator of the curve $B$. If we choose $A$ to be the point at infinity $(0,1)$, we can simplify the equation, but the sever prevent to choose points with $x=0$. For the 25519 curve, the order is not prime and there are points which have order 8. So if we give to the server one of those points we then obtain the following equation for verification:

$$8 S \cdot B = 8 \cdot R$$

I found the y coordinates of those point [here](https://gist.github.com/jedisct1/39f8dee6e38b12bb34f5). I used the curve equation to recover the x coordinate:

__________

```
     1
    2
    3
    4
    5
    6
```

| 

```
    sage: p = 2^255 - 19
    sage: F = GF(p)
    sage: y = 2707385501144840649318225287225658788936804267575313519463743609750303402022
    sage: x_squared = (1-y^2)/(y^2*(F(121665)/F(121666))-1)
    sage: sqrt(x_squared)
    14399317868200118260347934320527232580618823971194345261214217575416788799818
```  
  
---|---  
  
Since we are able to overwrite the value of $R$ we can simply send the public key and $R = S \cdot B$ to the server:

__________

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
```

| 

```
    from pwn import remote
    from Crypto.PublicKey import ECC
    
    r = remote("challs.polygl0ts.ch", 9001)
    
    print(r.recvline())
    for i in range(4):
        keyT = ECC.construct(curve='ed25519', point_x=14399317868200118260347934320527232580618823971194345261214217575416788799818, point_y=2707385501144840649318225287225658788936804267575313519463743609750303402022)
        rsp = r.recvline().decode()
        sig = bytes.fromhex(rsp)
        s = int.from_bytes(sig, 'little')
        R = ECC.EccKey(point=s * keyT._curve.G).export_key(format='raw')
        sig = keyT.export_key(format='raw') + R
        r.sendline(sig.hex().encode())
        print(r.recvline())
    
    print(r.recvline())
    print(r.recvall())
```  
  
---|---  
  
__

Which also gives the flag.

Updated on 2026-03-29 

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

[Read Markdown](https://sylvainpelissier.gitlab.io/posts/2024-12-09-lakectf-wild-signatures/index.md "Read Markdown")

[__](javascript:void\(0\); "Share on X")[__](javascript:void\(0\); "Share on Facebook")[__](javascript:void\(0\); "Share on 微博")

[Back](javascript:void\(0\);) | [Home](https://sylvainpelissier.gitlab.io/)

[__Black Alps 2024 CTF - SpongyAES](https://sylvainpelissier.gitlab.io/posts/2024-11-08-black-alps-spongyaes/ "Black Alps 2024 CTF - SpongyAES ")[HXP 38C3 CTF Circus and Cccircus __](https://sylvainpelissier.gitlab.io/posts/2024-12-28-hxp-38c3-ctf-circus/ "HXP 38C3 CTF Circus and Cccircus")
