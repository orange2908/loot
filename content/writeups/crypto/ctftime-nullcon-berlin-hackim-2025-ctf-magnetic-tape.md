---
title: "Magnetic tape - Nullcon Berlin HackIM 2025 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["cookies", "crypto", "web", "aes", "xor", "flask", "burp", "base64", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Alright, We're diving into Magnetic Tape from the nullcon HackIM CTF."
source:
  name: "CTFtime writeup #40407"
  url: "https://ctftime.org/writeup/40407"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-09-05-magnetic-tape-writeup"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "Magnetic tape"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** Magnetic tape
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** cookies, crypto, web
- **CTFtime:** <https://ctftime.org/writeup/40407>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-09-05-magnetic-tape-writeup>

---
## Magnetic tape - nullcon HackIM CTF Berlin 2025 Write-up

![Banner](https://writeups.thebusfactoris1.online/assets/files/magnet/image.png)

**Challenge:** Magnetic Tape  
**Category:** Crypto  
**Points:** 392  
**Author:** LTFZP

Alright, We're diving into `Magnetic Tape` from the nullcon HackIM CTF. This was a super fun crypto challenge disguised as a web app. The mission was to tamper with our session cookie, grant ourselves admin privileges, and snag the flag. Let's break it down.

### Introduction  
We were handed the source code, which is always a treat. The first stop was [**[magnetic_tape.py](http://magnetic_tape.py)**](https://writeups.thebusfactoris1.online/assets/files/magnet/magnetic_tape.tar), the main Flask application. A quick scroll revealed the treasure chest: the /get-flag endpoint.

```bash  
@app.route("/get-flag")  
@login_required  
def get_session():  
if not session["is_admin"]:  
abort(401)  
returns flag  
```

The condition is crystal clear: we need `session["is_admin"]` to be `True`. However, the `do_login()` function hardcodes this value to `False` upon login.

### in do_login()

```bash  
session["user_id"] = user['id']  
session["is_admin"] = False  
```

This means a direct login won't get us the flag. We have to mess with the session cookie itself. Time to pop the hood on [**[secure_session.py](http://secure_session.py)**](https://writeups.thebusfactoris1.online/assets/files/magnet/magnetic_tape.ta). This is where the magic (and the mistake) happens. The session is handled by a custom class, `CustomSessionInterface`, which uses:

Encryption: AES in Counter (CTR) mode.

Integrity Check: A 64-bit CRC (Cyclic Redundancy Check).

For anyone familiar with crypto, seeing **AES-CTR paired** with CRC for integrity is a huge red flag. It's like using duct tape to fix a leak in a submarine; it’s not going to hold against pressure.

Why is this combo so bad? **AES-CTR** is a stream cipher, which means it's malleable. If you flip a bit in the ciphertext, the corresponding bit in the decrypted plaintext also flips. The only thing stopping us from changing `is_admin: false` to `is_admin: true` is the integrity check. But CRC is also **"malleable"** in a cryptographic sense—it's linear. This property is its Achilles' heel, and it’s exactly what we're going to exploit.

### Forging the CRC  
The attack plan is a classic bit-flipping attack, made possible by forging the CRC checksum.

### The Theory  
The server encrypts a plaintext `P`, which is our session data M concatenated with its checksum: `P = M || CRC(M)`. The encryption is `C = E_k(P) = P XOR Keystream`. The server sends us the IV and C.

When we send back a modified cookie `C'`, the server decrypts it to get `P'= D_k(C') = C' XOR Keystream`. It then verifies if the last 8 bytes of `P'` (the received CRC) match the calculated CRC of the first part of `P'` (the received message).

Our goal is to craft a `C'` that decrypts to our desired plaintext, `P' = M' || CRC(M')`, where `M'` is our session with `"is_admin": true`.

Let's define a difference mask `delta = P XOR P'`. If we can calculate `delta`, we can find our forged ciphertext: `C' = C XOR delta`. The math works out because the XOR operations cancel, leaving us with `P'`.

So, what is `delta?`  
`delta = P XOR P' = (M || CRC(M)) XOR (M' || CRC(M'))`

This can be broken down into two parts:

The message part: `delta_M = M XOR M'`

The CRC part: `delta_CRC = CRC(M) XOR CRC(M')`

Here's the crucial weakness: because CRC is linear, `CRC(M) XOR CRC(M') = CRC(M XOR M') = CRC(delta_M)`. This is **huge!** It means we don't need to know the original message M or its CRC. We only need to know the change we want to make, which is `delta_M`.

Our final mask is `delta = delta_M || CRC(delta_M)`.

### The Attack  
Now, let's put it into practice.

1\. Get a valid cookie: Register a user, log in, and grab the session cookie from the browser or a proxy like Burp Suite.

2\. Define the change: The original JSON string in the session contains `..."is_admin":false}`. We want to change the substring `false to true`. The lengths must match: `false` is 5 bytes, and so is `true` (with a leading space).

3\. Craft the exploit: We write a script to calculate the `delta` and apply it to our captured cookie. The script will:

1\. Base64-decode the captured cookie and separate the IV from the ciphertext (C).

2\. Construct `delta_M` by creating a string of null bytes with the XOR difference `("false" XOR " true")` at the correct position. This requires some trial and error to find the offset of the `is_admin` field within the session data.

3\. Calculate `CRC(delta_M)`.

4\. Combine them to create the full mask: `delta = delta_M || CRC(delta_M)`.

5\. XOR the mask with the original ciphertext: `C' = C XOR delta`.

6\. Prepend the original IV and Base64-encode the result to get the forged cookie.

Here's a script that accomplishes this:  
```py  
import base64  
import binascii  
from universalCRC import crc

POLY = [  
62, 57, 55, 54, 53, 52, 47, 46, 45, 40, 39, 38, 37, 35, 33, 32, 31, 29,  
27, 24, 23, 22, 21, 19, 17, 13, 12, 10, 9, 7, 4, 1, 0,  
]  
POLY = sum(1 << d for d in POLY)  
IV_LENGTH = 16  
MAC_LENGTH = 8

def crc64(data):  
check_value = crc.compute_CRC(binascii.hexlify(data).decode("ascii"), POLY, 0, 0, 64, False, False)  
return check_value.to_bytes(8, "big")

def forge_cookie(original_cookie):  
decoded_cookie = base64.b64decode(original_cookie)  
iv = decoded_cookie[:IV_LENGTH]  
ciphertext = decoded_cookie[IV_LENGTH:]  
original_plaintext_part = b'false'  
forged_plaintext_part = b'13337'

delta_p = b'\0' * 64 + (bytes(a ^ b for a, b in zip(original_plaintext_part, forged_plaintext_part))) + b'\0'

delta_c = crc64(delta_p)

delta = delta_p + delta_c  
forged_ciphertext = bytes([a ^ b for a, b in zip(ciphertext, delta)])

forged_cookie_bytes = iv + forged_ciphertext  
forged_cookie = base64.b64encode(forged_cookie_bytes).decode("ascii")  
return forged_cookie

original_cookie = ""  
forged_cookie = forge_cookie(original_cookie)  
print(f"Forged admin cookie: {forged_cookie}")  
```  
Running this script gives us our golden ticket: a new session cookie with admin privileges.

#### Using the forged cookie from the script's output\  
```  
FORGED_COOKIE="1rr5/DTw5NaiwuajRTvpKIEriq7XQSz0b/VYbE/mt6NgnOvsh5OaWDgQoRNLFCBXZBwDyE5WqWnHGuNLytbm3ebVL6vCN9+nPNpH365D6iqZpTcplSxvv3Be1UGLrw=="  
```

#### Make the request with curl  
```  
GET /get-flag HTTP/1.1  
Host: 52.59.124.14:5005  
Cache-Control: max-age=0  
Accept-Language: en-US,en;q=0.9  
Upgrade-Insecure-Requests: 1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Accept-Encoding: gzip, deflate, br  
Cookie: webpy_session_id=e82377431f63b027adb5f0265cf223b39d2a8007; session=LAc1dRgx9/km3ZeYAORoVUNLAdRpIaJgAhFGP1R7tbftJbtUVTuuEgpknKEQNBcVzTN0aUI6q3XqoNyWAt/niZywxh/0UXZu5Ik7gkwhqQcKyT9SzDybRALdRNUS5w==  
Connection: keep-alive  
```

The server, completely fooled by our carefully crafted cookie, happily hands over the flag.  
```  
HTTP/1.1 200 OK  
Content-Type: text/html; charset=utf-8  
Content-Length: 35  
Set-Cookie: session=V2vmDrm5pw/HzjWyDOjIc5XHoz5vzadug4jlYD3QfmyKPjz2vxWVLDJ5vU4VjzRw6VIEjqxa/6PQNPhJRRVeNrBmOXMVUPKsUYjajMn36IbeCGQHOUMYKKDi6bxsow==; Path=/

ENO{null_1s_nu1l_d8683c9163965e2b}  
```  
And just like that, we're in. This was a fantastic challenge illustrating a textbook crypto vulnerability.

#### FLAG  
```  
FLAG : ENO{null_1s_nu1l_d8683c9163965e2b}  
```
