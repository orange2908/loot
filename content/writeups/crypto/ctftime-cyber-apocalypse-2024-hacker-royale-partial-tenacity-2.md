---
title: "Partial Tenacity - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "proof-of-work", "partial", "tenacity", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "We are given the Python source code that encrypts the flag:"
source:
  name: "CTFtime writeup #39007"
  url: "https://ctftime.org/writeup/39007"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/partial-tenacity/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Partial Tenacity"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Partial Tenacity
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/39007>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/partial-tenacity/>

---
We are given the Python source code that encrypts the flag:

`

```
    from secret import FLAG
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    
    class RSACipher:
        def __init__(self, bits):
            self.key = RSA.generate(bits)
            self.cipher = PKCS1_OAEP.new(self.key)
        
        def encrypt(self, m):
            return self.cipher.encrypt(m)
    
        def decrypt(self, c):
            return self.cipher.decrypt(c)
    
    cipher = RSACipher(1024)
    
    enc_flag = cipher.encrypt(FLAG)
    
    with open('output.txt', 'w') as f:
        f.write(f'n = {cipher.key.n}\n')
        f.write(f'ct = {enc_flag.hex()}\n')
        f.write(f'p = {str(cipher.key.p)[::2]}\n')
        f.write(f'q = {str(cipher.key.q)[1::2]}')
```

`

We also have the output of the script:

`

```
    n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
    ct = 7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476
    p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
    q = 15624342005774166525024608067426557093567392652723175301615422384508274269305
```

`

## Source code analysis

The server uses a standard RSA-OAEP encryption to encrypt the flag. The thing is that we are given some information about the private key (prime numbers  and ):

`

```
        f.write(f'p = {str(cipher.key.p)[::2]}\n')
        f.write(f'q = {str(cipher.key.q)[1::2]}')
```

`

The above code means that we have some digits of both prime numbers represented as decimal numbers. But they are alternated.

We can express the above as follows:

Where  is the number of digits;  and  are the known digits from  and ; and  and  are the unknown digits of  and .

## Solution

Since we know that , the following condition must hold:

As a result, we can use modulo powers of  to extract each unknown digit, because:

Once we find , we can increase the power of  and find :

Then :

And so on and so forth until we have all digits of  and .

### Implementation

The implementation is quite simple, using a loop and testing if condition matches for  or :

`

```
    #!/usr/bin/env python3
    
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    
    n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
    ct = bytes.fromhex('7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476')
    p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
    q = 15624342005774166525024608067426557093567392652723175301615422384508274269305
    
    p_digits = []
    q_digits = []
    
    for d in str(p):
        p_digits.append(d)
        p_digits.append('0')
    
    p = int(''.join(p_digits[:-1]))
    
    for d in str(q):
        q_digits.append('0')
        q_digits.append(d)
    
    q_digits.append('0')
    
    q = int(''.join(q_digits))
    
    for i in range(len(q_digits)):
        if i % 2 == 0:
            while n % (10 ** (i + 1)) != (p * q) % (10 ** (i + 1)):
                q += 10 ** i
        else:
            while n % (10 ** (i + 1)) != (p * q) % (10 ** (i + 1)):
                p += 10 ** i
    
    assert p * q == n
    
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    cipher = PKCS1_OAEP.new(RSA.construct((n, e, d)))
    pt = cipher.decrypt(ct)
    print(pt.decode())
```

`

We initially set the unknown digits to , so on each iteration, when the condition fails, we add  to the value of  or .

## Flag

If we run the above script, we will get the flag:

`

```
    $ python3 solve.py
    HTB{v3r1fy1ng_pr1m3s_m0dul0_p0w3rs_0f_10!}
```

`

The full script can be found in here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/blob/main/HTB%20Cyber%20Apocalypse/Crypto/Partial%20Tenacity/solve.py).
