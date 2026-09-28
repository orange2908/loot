---
title: "RSA - n00bzCTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "low-exponent", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "An attachment got us everything we need to decrypt ciphertext to plaintext again, here are what we got"
source:
  name: "CTFtime writeup #39386"
  url: "https://ctftime.org/writeup/39386"
original_source: "https://github.com/ChickenLoner/Write-Up/blob/main/Unlisted%20Labs/n00bz%20CTF%202024%20Write-up%20(ByTheW4y%20Team).md"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "RSA"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** RSA
- **Author team:** ByTheW4y
- **CTFtime tags:** crypto, rsa
- **CTFtime:** <https://ctftime.org/writeup/39386>
- **Original writeup:** <https://github.com/ChickenLoner/Write-Up/blob/main/Unlisted%20Labs/n00bz%20CTF%202024%20Write-up%20(ByTheW4y%20Team).md>

---
![pic1](<https://github.com/ChickenLoner/Write-Up/raw/main/_resources/d351627f8e55ff12500d3cffccc8f71b.png>)

![pic2](<https://raw.githubusercontent.com/ChickenLoner/Write-Up/main/_resources/7f602cc4944794a45d74671227358dbb.png>)

An [attachment](https://static.n00bzunit3d.xyz/Crypto/RSA/encryption.txt) got us everything we need to decrypt ciphertext to plaintext again, here are what we got

e is public exponent (used for encryption)  
n is modulus  
c is ciphertext  
Because e is 3 (small number) then if plaintext is also small enough, we can decrypt ciphertext easily by computing the integer cube root of c

and here is the python script that will do just that

```  
import gmpy2

# Given values  
e = 3  
n = 135112325288715136727832177735512070625083219670480717841817583343851445454356579794543601926517886432778754079508684454122465776544049537510760149616899986522216930847357907483054348419798542025184280105958211364798924985051999921354369017984140216806642244876998054533895072842602131552047667500910960834243  
c = 13037717184940851534440408074902031173938827302834506159512256813794613267487160058287930781080450199371859916605839773796744179698270340378901298046506802163106509143441799583051647999737073025726173300915916758770511497524353491642840238968166849681827669150543335788616727518429916536945395813

# Compute cube root  
m, exact = gmpy2.iroot(c, e)

if exact:  
print("The message is:", m)  
else:  
print("No direct cube root found, message might be larger.")

# Assuming m is found and is an integer  
plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')  
print("Decoded message:", plaintext.decode())  
```

![pic3](<https://github.com/ChickenLoner/Write-Up/raw/main/_resources/d471ddf06455aae732c48c5604c89ece.png>)

Then execute it to get a flag

```  
n00bz{crypt0_1s_1nc0mpl3t3_w1th0ut_rs4!!}  
```
