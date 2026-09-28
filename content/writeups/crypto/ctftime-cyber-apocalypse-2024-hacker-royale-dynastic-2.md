---
title: "Dynastic - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "dynastic", "classical", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Hi All, Challenge description is like below:"
source:
  name: "CTFtime writeup #39345"
  url: "https://ctftime.org/writeup/39345"
original_source: "https://medium.com/@embossdotar/cyber-apocalypse-2024-hacker-royale-crypto-dynastic-7395ab5cd3ea"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Dynastic"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Dynastic
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39345>
- **Original writeup:** <https://medium.com/@embossdotar/cyber-apocalypse-2024-hacker-royale-crypto-dynastic-7395ab5cd3ea>

---
Hi All, Challenge description is like below:

“You find yourself trapped inside a sealed gas chamber, and suddenly, the air is pierced by the sound of a distorted voice played through a pre-recorded tape. Through this eerie transmission, you discover that within the next 15 minutes, this very chamber will be inundated with lethal hydrogen cyanide. As the tape’s message concludes, a sudden mechanical whirring fills the chamber, followed by the ominous ticking of a clock. You realise that each beat is one step closer to death. Darkness envelops you, your right hand restrained by handcuffs, and the exit door is locked. Your situation deteriorates as you realise that both the door and the handcuffs demand the same passcode to unlock. Panic is a luxury you cannot afford; swift action is imperative. As you explore your surroundings, your trembling fingers encounter a torch. Instantly, upon flipping the switch, the chamber is bathed in a dim glow, unveiling cryptic letters etched into the walls and a disturbing image of a Roman emperor drawn in blood. Decrypting the letters will provide you the key required to unlock the locks. Use the torch wisely as its battery is almost drained out!”, Source: <https://ctf.hackthebox.com/event/details/cyber-apocalypse-2024-hacker-royale-1386>

As you can see, with this task you have to download some files (crypto_dynastic.zip). There are “output.txt” and “[source.py](http://source.py)” files.

“[source.py](http://source.py)” file:

```  
from secret import FLAG  
from random import randint

def to_identity_map(a):  
return ord(a) — 0x41

def from_identity_map(a):  
return chr(a % 26 + 0x41)

def encrypt(m):  
c = ‘’  
for i in range(len(m)):  
ch = m[i]  
if not ch.isalpha():  
ech = ch  
else:  
chi = to_identity_map(ch)  
ech = from_identity_map(chi + i)  
c += ech  
return c

with open(‘output.txt’, ‘w’) as f:  
f.write(‘Make sure you wrap the decrypted text with the HTB flag format :-]\n’)  
f.write(encrypt(FLAG))  
```

and “output.txt” file:

```  
Make sure you wrap the decrypted text with the HTB flag format :-]

DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL  
```

This Python script contains three functions:

(1) to_identity_map(a): Converts a character a to an integer by subtracting the ASCII value of ‘A’ (0x41).

(2) from_identity_map(a): Converts an integer a back to a character by taking the remainder when divided by 26 and adding the ASCII value of ‘A’.

(3) encrypt(m): Takes a message m, processes each character, and returns the encrypted message.

The encryption process involves converting each alphabetic character to its corresponding integer using to_identity_map, then adding the current index (i) and converting it back to a character using from_identity_map. Non-alphabetic characters are left unchanged.

To decrypt it and obtain the flag, we need to reverse the encryption process.

Solution — code (Python):

```  
def to_identity_map(a):  
return ord(a) — 0x41

def from_identity_map(a):  
return chr(a % 26 + 0x41)

def decrypt(c):  
m = ‘’  
for i in range(len(c)):  
ch = c[i]  
if not ch.isalpha():  
m += ch  
else:  
chi = to_identity_map(ch)  
m += from_identity_map(chi — i)  
return m

encrypted_text = “DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL”  
decrypted_text = decrypt(encrypted_text)  
print(“Decrypted Text:”, decrypted_text)  
```

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*WIhe6CPb-ILfja0BWDIjgg.png>)

Source: <https://www.online-python.com/>

FLAG: 

**HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!_IT_IS_SIMILAR_TO_CAESAR_CIPHER}**

Bonus info:

Tabula recta: <https://en.wikipedia.org/wiki/Tabula_recta>

Caesar cipher: <https://en.wikipedia.org/wiki/Caesar_cipher>

Tool to decrypt/encrypt Trithemius: <https://www.dcode.fr/trithemius-cipher>

I hope you enjoy!
