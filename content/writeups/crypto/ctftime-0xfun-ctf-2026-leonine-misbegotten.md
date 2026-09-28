---
title: "Leonine Misbegotten - 0xFUN CTF 2026"
category: "crypto"
type: "writeup"
tags: ["crypto", "base64", "base32", "leonine", "misbegotten", "0xfun-ctf", "0xfun-ctf-2026", "2026", "ctf-writeup"]
summary: "Leonine Misbegotten | 0xFun CTF 2026"
source:
  name: "CTFtime writeup #40674"
  url: "https://ctftime.org/writeup/40674"
original_source: "https://axl0t0l.github.io/posts/0xfun/LeonineMisbegotten"
ctf:
  name: "0xFUN CTF 2026"
  year: 2026
  challenge: "Leonine Misbegotten"
---

## Metadata

- **CTF:** 0xFUN CTF 2026
- **Task:** Leonine Misbegotten
- **Author team:** 0xDr460nZ
- **CTFtime:** <https://ctftime.org/writeup/40674>
- **Original writeup:** <https://axl0t0l.github.io/posts/0xfun/LeonineMisbegotten>

---
Leonine Misbegotten | 0xFun CTF 2026 __

Contents __

Leonine Misbegotten | 0xFun CTF 2026

__

[![](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)

##  Overview __

  * **Platform:** [0xFun](https://ctf.0xfun.org/)
  * **Challenge:** [Leonine Misbegotten](https://ctf.0xfun.org/challenges#Leonine%20Misbegotten-64)
  * **Categories:** Crypto
  * **Rating:** 9/10
  * **Difficulty:** Easy
  * **Solving Time:** ~20 Minutes


## Challenge __

> “ _At the end of Castle Morne awaits a fearsome lion with a goofy tail. His attacks come fast, feel random, yet follow a careful rhythm._ ”

## Walkthrough __

### Recon __

If we look at this code it doesn’t look really complicated just simple encoding logic with checksums.

####  The Code __

____

`

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
```

| 

```
     from base64 import b16encode, b32encode, b64encode, b85encode
    from hashlib import sha1
    from random import choice
    from secret import flag
    
    SCHEMES = [b16encode, b32encode, b64encode, b85encode]
    
    ROUNDS = 16
    current = flag.encode()
    for _ in range(ROUNDS):
        checksum = sha1(current).digest() # this is to help you check the integrity of your decryption
        current = choice(SCHEMES)(current) 
        current += checksum
    
    with open("output", "wb") as f:
        f.write(current)
```  
  
---|---  
`

#### Code Output __

[![Get files here!!](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Leonine-Misbegotten/output)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Leonine-Misbegotten/output)

### Solution Approach __

> “ _Flag format:`0xfum{}`_”

#### Encoding Script __

**The Setup:**

It starts with the flag. It defines four possible encoding schemes: Base16, Base32, Base64, and Base85. The Loop (The “Wrapping” Phase): The script runs 16 times (ROUNDS = 16). In each round:

  * Checksum: It calculates a sha1 hash of the current data. This hash is always 20 bytes long.
  * Encoding: It randomly picks one of the four schemes and encodes the data.
  * Appending: It tacks the 20-byte checksum onto the end of the newly encoded string.


The Output: After 16 rounds of this, the final, heavily encoded string is saved to a file named output.

#### Decoding Script Logic __

To get the flag back, you have to work backward from the output file. Since each round adds the checksum after encoding, the logic for one decryption step looks like this:

  * Separate: Take the last 20 bytes off the data—that’s your checksum.
  * Identify & Decode: Try decoding the remaining string using all four methods (Base16, 32, 64, 85).
  * Verify: For each successful decode, calculate the SHA1 hash of the result. If it matches the checksum you sliced off in step 1, you know you found the correct scheme for that layer.
  * Repeat: Do this 16 times until you hit the original flag string.


> You can ask any AI to write you the script.

#### Decoding Script __

____

`

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
    19
    20
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
    41
```

| 

```
     import base64
    import hashlib
    
    # Load the encoded data from the output file
    with open("output", "rb") as f:
        current = f.read()
    
    # The four schemes used in the original script
    SCHEMES = [
        base64.b16decode,
        base64.b32decode,
        base64.b64decode,
        base64.b85decode
    ]
    
    # Work backwards through the 16 rounds
    for i in range(16):
        # The checksum is the last 20 bytes
        checksum = current[-20:]
        # The encoded data is everything before the checksum
        encoded_data = current[:-20]
        
        found = False
        for decode_func in SCHEMES:
            try:
                # Attempt to decode
                decoded = decode_func(encoded_data)
                # Verify the integrity using the SHA1 checksum
                if hashlib.sha1(decoded).digest() == checksum:
                    current = decoded
                    found = True
                    print(f"Round {16-i} decrypted successfully.")
                    break
            except Exception:
                continue
                
        if not found:
            print(f"Failed to decrypt at round {16-i}")
            break
    
    print(f"\nFlag: {current.decode()}")
```  
  
---|---  
`

and there we got the flag!! [![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Leonine-Misbegotten/flag.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Leonine-Misbegotten/flag.png)

#### Flag __

`0xfun{p33l1ng_l4y3rs_l1k3_an_0n10n}`

**_Hope you enjoined the writeup, Don’t forget to leave a comment or a star on the[github repo](https://github.com/Axl0t0l) (;_**

__[0xFun CTF 2026](https://axl0t0l.github.io/categories/0xfun-ctf-2026/), [WarmUp](https://axl0t0l.github.io/categories/warmup/)

__[Crypto](https://axl0t0l.github.io/tags/crypto/)

This post is licensed under [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) by the author.

Share [ __](https://twitter.com/intent/tweet?text=Leonine%20Misbegotten%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xfun%2FLeonineMisbegotten "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Leonine%20Misbegotten%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&u=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xfun%2FLeonineMisbegotten "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xfun%2FLeonineMisbegotten&text=Leonine%20Misbegotten%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l "Telegram") __
