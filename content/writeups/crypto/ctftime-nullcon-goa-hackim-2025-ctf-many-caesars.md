---
title: "many caesars - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "wordlists", "many", "caesars", "classical", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "It is just a 65 shift cipher with custom wordlist."
source:
  name: "CTFtime writeup #40030"
  url: "https://ctftime.org/writeup/40030"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "many caesars"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** many caesars
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40030>

---
It is just a 65 shift cipher with custom wordlist. My solution required a lot of manual work:

```  
import string

chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '+/='

def caesar_decrypt_chunk(chunk):  
"""  
Tries all 65 possible shifts on the given ciphertext chunk and returns possible plaintext words.  
"""  
possible_plaintexts = []  
  
for shift in range(len(chars)): # Try all 65 shifts  
decrypted = ''.join(chars[(chars.index(c) - shift) % len(chars)] for c in chunk)  
  
# Check if all decrypted characters are in 'a-z' (valid plaintext)  
if all(c in string.ascii_lowercase for c in decrypted):  
possible_plaintexts.append((shift, decrypted))  
  
return possible_plaintexts

def main():  
print("CTF Chunk Decryptor - Try all 65 shifts and find valid words")  
while True:  
chunk = input("\nEnter encrypted chunk (or 'exit' to quit): ").strip()  
if chunk.lower() == 'exit':  
break  
  
results = caesar_decrypt_chunk(chunk)  
  
if results:  
print(f"\nPossible plaintext words for chunk '{chunk}':")  
for shift, word in results:  
print(f" Shift {shift:2}: {word}")  
else:  
print(f"\nNo valid plaintext found for chunk '{chunk}'.")  
  
print("\nGoodbye!")

if __name__ == "__main__":  
main()  
```

Decrypted text: `hacker ethics is a set of principles that guide the behaviour of individuals who explore and manipulate computer systems, often emphasizing curiosity, creativity, and the pursuit of knowledge. rooted in values such as openness, free access to information, and the belief in using skills to improve systems rather than harm them, hacker ethics encourages responsible and ethical use of technology. it advocates for transparency, collaboration, and respecting privacy, while discouraging malicious activities like stealing data or causing damage. these principles aim to foster innovation and a positive impact on society through ethical and constructive hacking.`

```  
import string

chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '+/='

def caesar_decrypt_chunk(chunk):  
"""  
Tries all 65 possible shifts on the given ciphertext chunk and returns possible plaintext words.  
"""  
possible_plaintexts = []  
  
for shift in range(len(chars)): # Try all 65 shifts  
decrypted = ''.join(chars[(chars.index(c) - shift) % len(chars)] for c in chunk)  
  
# Check if all decrypted characters are in 'a-z' (valid plaintext)  
if all(c in string.ascii_lowercase for c in decrypted):  
possible_plaintexts.append((shift, decrypted))  
  
return possible_plaintexts

def main():  
print("CTF Chunk Decryptor - Try all 65 shifts and find valid words")  
while True:  
chunk = input("\nEnter encrypted chunk (or 'exit' to quit): ").strip()  
if chunk.lower() == 'exit':  
break  
  
results = caesar_decrypt_chunk(chunk)  
  
if results:  
print(f"\nPossible plaintext words for chunk '{chunk}':")  
for shift, word in results:  
print(f" Shift {shift:2}: {word}")  
else:  
print(f"\nNo valid plaintext found for chunk '{chunk}'.")  
  
print("\nGoodbye!")

if __name__ == "__main__":  
main()  
```

`ENO{th3_d1ffer3nce5_m4ke_4ll_th3_diff3renc3}`
