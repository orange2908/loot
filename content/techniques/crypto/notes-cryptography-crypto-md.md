---
title: "Crypto (Cryptography)"
category: "crypto"
subcategory: "rsa"
type: "technique"
tags: ["my-notes", "personal", "rsa", "aes", "sage", "cbc", "length-extension", "chinese-remainder", "factordb", "rsactftool", "proof-of-work", "base64", "exec", "crypto", "cryptography"]
summary: "https://github.com/bwall/HashPump"
source:
  name: "Personal notes"
origin_path: "Cryptography/Crypto.md"
---

### Read the content of a `.pem` file

```python
from Crypto.PublicKey import RSA

public_key = RSA.importKey(open('pubkey.pem', 'r').read())
e = public_key.e
n = public_key.n
```
or
```python
key = open("./public_key.pem.txt", "rb").read()

n = RSA.importKey(key).n
e = RSA.importKey(key).e
```
or
```bash
python ~/Desktop/Tools/crypto/RsaCtfTool/RsaCtfTool.py --publickey public.crt --dumpkey
```
### using openssl
```bash
openssl rsa -noout -text -inform PEM -in public_key.pem.txt -pubin
```
### using RsaCtfTool
```bash
python ~/Desktop/tools/crypto/RsaCtfTool/RsaCtfTool.py --key public_key.pem.txt --dumpkey
```
### decrypt data using AES_CBC mode in python
```python
from Crypto.Cipher import AES
import base64

# AES key and initialization vector
key = b'0123456789abcdef'
iv = b'0123456789abcdef'

# Encrypted data
ciphertext = base64.b64decode('Encrypted Data')

# Create AES cipher
cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt the data
plaintext = cipher.decrypt(ciphertext)

# Strip off the padding
plaintext = plaintext.rstrip(b'\0')

print(plaintext)
```

---
## Formats conversions

> **Info** Certificates
> undefined  
> [https://book.hacktricks.xyz/crypto-and-stego/certificates](https://book.hacktricks.xyz/crypto-and-stego/certificates)  

### Build a privatekey.pem file from RSA
```python
from Crypto.PublicKey import RSA

d = 79646471534494861299926464439293255857067279657625118443808906841029783076473886211884569855344965660832579121253866444104192203504992631986673288039935410959097759046025578940090851230345607520332638715232976191697044569275251154864048205032943795202257898469096962895207677427705087064765701537148303893313
n = 150140677816147665104219084736753210294673482912091623639530125054379822052662632476220418069658373540642718111649733795871151252404840997598533258881471779382418788567883517594075575444723340506445280678466322096113052425236787558022472785685579744210805862764465110689084328509029822107730392445215781001579
e = 65537
p = 11443069641880629381891581986018548808448150675612774441982091938562801238612124445967724562059877882869924090566492089872161438646198325341704520958011761
q = 13120664517031861557695339067275706831429518210212092859212127044658713747906482358428924486662467583986570766086011893335839637764790393666582606794678939

key = RSA.construct((n, e, d, p, q))

with open('private.pem', 'wb') as f:
    f.write(key.export_key(format='PEM'))
```

### get modulus from a certificate with openssl
```bash
openssl x509 -in certificate.pub -modulus
```
### generate privatekey using RsaCtfTool
```bash
./RsaCtfTool.py --publickey key.pub --private --attack factordb > private.key
```

## hash length extension attack
https://github.com/bwall/HashPump
# Chinese Remainder Theorem - CRT
## sage
```python
sage: from Crypto.Util.number import long_to_bytes as l2b
sage: l2b(crt([c1, c2, c3],[p1, p2, p3]))
b'DH{Th3_Ch1n35e_r3m4iNd3r_tHe0r3m_w4s_qu1T3_345y_r1ght??_:)}'
```
## python
```python
from sympy import mod_inverse
from Crypto.Util.number import long_to_bytes

def crt(c1, p1, c2, p2, c3, p3):
    n = p1 * p2 * p3
    n1 = n // p1
    n2 = n // p2
    n3 = n // p3

    m1 = mod_inverse(n1, p1)
    m2 = mod_inverse(n2, p2)
    m3 = mod_inverse(n3, p3)

    x = (c1 * n1 * m1 + c2 * n2 * m2 + c3 * n3 * m3) % n
    return x

p1 = 1527207470243143973741530105910986024271649986608148657294882537828034327858594844987775446712917007186537829119357070864918869
p2 = 2019864244456120206428956645997068464122219855220655920467990311571156191223237121636244541173449544034684177250532278907347407
p3 = 1801109020443617827324680638861937237596639325730371475055693399143628803572030079812427637295108153858392360647248339418361407
c1 = 232762450308730030838415167305062079887914561751502831059133765333100914083329837666753704309116795944107100966648563183291808
c2 = 869189375217585206857269997483379374418043159436598804873841035147176525138665409890054486560412505207030359232633223629185304
c3 = 1465704473460472286244828683610388110862719231828602162838215555887249333131331510519650513265133531691347657992103108331793683

flag = crt(c1, p1, c2, p2, c3, p3)
print(long_to_bytes(flag))

# DH{Th3_Ch1n35e_r3m4iNd3r_tHe0r3m_w4s_qu1T3_345y_r1ght??_:)}
```
Or
```python
# python3
with open("output.txt", "r") as f: exec(f.read())

N = p1*p2*p3
N1 = N//p1
N2 = N//p2
N3 = N//p3

M1 = pow(N1, -1, p1)
M2 = pow(N2, -1, p2)
M3 = pow(N3, -1, p3)

m = (N1*M1*c1 + N2*M2*c2 + N3*M3*c3) % N
print(int(m).to_bytes((m.bit_length()+7)>>3, byteorder='big').decode())
```

---

*From your own notes: `Cryptography/Crypto.md`*
