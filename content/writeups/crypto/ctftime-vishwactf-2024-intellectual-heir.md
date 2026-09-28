---
title: "Intellectual Heir - VishwaCTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "proof-of-work", "intellectual", "heir", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "The Python code given converts characters to their ASCII values:"
source:
  name: "CTFtime writeup #39532"
  url: "https://ctftime.org/writeup/39532"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/Intellectual%20Heir.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "Intellectual Heir"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** Intellectual Heir
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39532>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/Intellectual%20Heir.pdf>

---
Solution:  
The Python code given converts characters to their ASCII values:

```  
def str_to_ass(input_string):   
return ''.join([str(ord(char)) for char in input_string])  
```  
The challenge involves understanding the RSA encryption and decryption. After applying sine and cosine functions to binary representations of two primes p and q, the values are stored in two files. The final task is to decrypt the given encrypted message using RSA and recover the combination for the safe.

Key Steps:

Load the sine and cosine data from the files and reverse the transformation to get the binary representations of p and q.  
Calculate n = p * q, phi = (p - 1) * (q - 1), and d = inverse(e, phi) where e = 65537.  
Decrypt the message using pow(encrypted, d, n) and convert the resulting ASCII values to the flag.  
Decrypted Message:  
Y0U_@R3_T#3_W0RT#Y_OF_3

```  
Flag:  
VishwaCTF{Y0U_@R3_T#3_W0RT#Y_OF_3}  
```
