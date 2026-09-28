---
title: "Vinegar 2 - n00bzCTF 2024"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "vigenere", "vinegar", "classical", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "\\- https://static.n00bzunit3d.xyz/Crypto/Vinegar2/chall.py"
source:
  name: "CTFtime writeup #39388"
  url: "https://ctftime.org/writeup/39388"
original_source: "https://github.com/ChickenLoner/Write-Up/blob/main/Unlisted%20Labs/n00bz%20CTF%202024%20Write-up%20(ByTheW4y%20Team).md"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Vinegar 2"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Vinegar 2
- **Author team:** ByTheW4y
- **CTFtime tags:** crypto, vigenere
- **CTFtime:** <https://ctftime.org/writeup/39388>
- **Original writeup:** <https://github.com/ChickenLoner/Write-Up/blob/main/Unlisted%20Labs/n00bz%20CTF%202024%20Write-up%20(ByTheW4y%20Team).md>

---
![p1](<https://github.com/ChickenLoner/Write-Up/raw/main/_resources/10648c980ce2658350931614eb2abe78.png>)

![p2](<https://github.com/ChickenLoner/Write-Up/raw/main/_resources/7153cfc741ff8ce55948d5112e2e6801.png>)

**Attachment**:   
\- https://static.n00bzunit3d.xyz/Crypto/Vinegar2/[chall.py](http://chall.py)   
\- https://static.n00bzunit3d.xyz/Crypto/Vinegar2/enc.txt

We were provided with a script to encrypt content of a flag to ciphertext and a ciphertext

And since we already got a key and know which encryption that was using, we can write a new script to reverse it back to plaintext like this

```  
alphanumerical = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}_?'  
matrix = []  
for i in alphanumerical:  
matrix.append([i])

idx=0  
for i in alphanumerical:  
matrix[idx][0] = (alphanumerical[idx:len(alphanumerical)] + alphanumerical[0:idx])  
idx += 1

key = '5up3r_s3cr3t_k3y_f0r_1337h4x0rs_r1gh7?'  
ciphertext = '*fa4Q(}$ryHGswGPYhOC{C{1)&_vOpHpc2r0({'

assert len(key) == len(ciphertext)

key_arr = []  
for y in key:  
for i in range(len(alphanumerical)):  
if matrix[i][0][0] == y:  
key_arr.append(i)

dec_arr = []  
for i in range(len(ciphertext)):  
char = ciphertext[i]  
key_index = key_arr[i]  
for j in range(len(alphanumerical)):  
if matrix[j][0][key_index] == char:  
dec_arr.append(matrix[j][0][0])  
break

decrypted_flag = ''.join(dec_arr)  
print(decrypted_flag)  
```

![p3](<https://github.com/ChickenLoner/Write-Up/raw/main/_resources/5a6280c48ee42940271939da91271b76.png>)

Execute it to get a flag

```  
n00bz{4lph4num3r1c4l_1s_n0t_4_pr0bl3m}  
```
