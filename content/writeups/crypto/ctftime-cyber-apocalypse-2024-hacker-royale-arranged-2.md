---
title: "Arranged - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "ecc", "common-factor", "gcd", "sage", "cbc", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "We are given the SageMath source code to encrypt the flag:"
source:
  name: "CTFtime writeup #39006"
  url: "https://ctftime.org/writeup/39006"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/arranged/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Arranged"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Arranged
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/39006>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/arranged/>

---
We are given the SageMath source code to encrypt the flag:

`

```
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Util.number import long_to_bytes
    from hashlib import sha256
    
    from secret import FLAG, p, b, priv_a, priv_b
    
    F = GF(p)
    E = EllipticCurve(F, [726, b])
    G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)
    
    A = G * priv_a
    B = G * priv_b
    
    print(A)
    print(B)
    
    C = priv_a * B
    
    assert C == priv_b * A
    
    # now use it as shared secret
    secret = C[0]
    
    hash = sha256()
    hash.update(long_to_bytes(secret))
    
    key = hash.digest()[16:32]
    iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    encrypted = cipher.encrypt(pad(FLAG, 16))
    print(encrypted)
```

`

Moreover, we have the output of the script:

`

```
    (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997 : 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696 : 1)
    (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734 : 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865 : 1)
    b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'
```

`

## Source code analysis

The server uses ECC for a Diffie-Hellman key exchange (ECDH). It is using a custom elliptic curve, wich unknown parameters  and  (notice that ), so

The server takes a known generator point  and uses private numbers  and  to compute  and . We are given these points  and  (and we know  from the source code).

After that, the shared secret is just the  coordinate of , which is also equal to . That’s how ECDH works, in general terms.

## Solution

The first thing we need to operate with the points in the curve is to actually find the curve parameters  and .

### Finding curve parameters

Notice that we already have three points that lie on the curve, so we have three equations that hold:

If we subtract the three equations to eliminate , we get these two:

If we arrange the equations we have:

What we see here is that we have two results that are congruent to , which means that both results are divisible by . As a result, both results share a common factor , so we can find  using the greatest common devisor (GCD). Well, more precisely, the GCD will output a multiple of , but this time it is just :

`

```
    $ sage -q
    sage: Gx, Gy = (9266444370006042174473166558572022974025725593685389789128881064194700114878783516673806793236640623625249672428198101125248803018820546824626
    ....: 85841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702
    ....: 851115715803253)
    ....: Ax, Ay = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599
    ....: 399265706997, 245615684135759032025121476180756956227160395340389423040157794181784404377493536330991954253211097273199654032849256596731338389586513019
    ....: 0496346350907696)
    ....: Bx, By = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590
    ....: 582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677
    ....: 407220354869865)
    sage:
    sage: a = 726
    sage:
    sage: p = gcd(
    ....:     Gy ** 2 - Ay ** 2 - Gx ** 3 - a * Gx + Ax ** 3 + a * Ax,
    ....:     Gy ** 2 - By ** 2 - Gx ** 3 - a * Gx + Bx ** 3 + a * Bx,
    ....: )
    sage: is_prime(p)
    True
```

`

Now, it is trivial to find  with a single point:

`

```
    sage: b = (Gy ** 2 - Gx ** 3 - a * Gx) % p
```

`

Now we can define the elliptic curve and use the above coordinates as points on the curve:

`

```
    sage: E = EllipticCurve(GF(p), [a, b])
    sage: G, A, B = E(Gx, Gy), E(Ax, Ay), E(Bx, By)
```

`

### ECDLP

Now, we must solve the ECDLP in order to find one of  or . The first thing we need is find the order of , which will determine if we can solve the ECDLP easily or not:

`

```
    sage: G.order()
    11
```

`

Oh! That’s a very small order! This is not good for ECDH, because it means that , the “point at infinity” (the identity element on the elliptic curve group).

As a result, no matter how large are  or , because we can express any of them as , for some integers  and  with .

As a result,

The same happens with , so we can simply try different values of  (from  to ) and see if  equals , and the same with :

`

```
    sage: for priv_a in range(11):
    ....:     if priv_a * G == A:
    ....:         break
    ....:
    sage: for priv_b in range(11):
    ....:     if priv_b * G == B:
    ....:         break
    ....:
    sage: C = priv_a * B
    sage: C == priv_b * A
    True
```

`

We have got the shared secret, so we can decrypt the flag with AES and the key derived from the shared secret.

## Flag

Here’s the flag:

`

```
    sage: from Crypto.Cipher import AES
    sage: from Crypto.Util.Padding import unpad
    sage: from Crypto.Util.number import long_to_bytes
    sage: from hashlib import sha256
    sage:
    sage: secret = int(C[0])
    sage:
    sage: h = sha256()
    sage: h.update(long_to_bytes(secret))
    sage:
    sage: key = h.digest()[16:32]
    sage: iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
    sage: cipher = AES.new(key, AES.MODE_CBC, iv)
    sage:
    sage: encrypted = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f
    ....: \xab'
    sage:
    sage: decrypted = unpad(cipher.decrypt(encrypted), 16)
    sage: print(decrypted.decode())
    HTB{0rD3r_mUsT_b3_prEs3RveD_!!@!}
```

`
