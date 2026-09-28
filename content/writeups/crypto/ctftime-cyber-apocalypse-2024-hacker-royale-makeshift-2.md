---
title: "Makeshift - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
type: "writeup"
tags: ["crypto", "makeshift", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Let's take a look at what we've been given."
source:
  name: "CTFtime writeup #38986"
  url: "https://ctftime.org/writeup/38986"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Makeshift"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Makeshift
- **Author team:** D0M BU$TЄR$
- **CTFtime:** <https://ctftime.org/writeup/38986>

---
> Weak and starved, you struggle to plod on. Food is a commodity at this stage, but you can’t lose your alertness - to do so would spell death. You realise that to survive you will need a weapon, both to kill and to hunt, but the field is bare of stones. As you drop your body to the floor, something sharp sticks out of the undergrowth and into your thigh. As you grab a hold and pull it out, you realise it’s a long stick; not the finest of weapons, but once sharpened could be the difference between dying of hunger and dying with honour in combat.

Let's take a look at what we've been given.

```plaintext  
!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB  
```

The first thing I noticed, is that we can clearly see HTB, and both curly braces in the encrypted flag ourselves, meaning we have an anagram that we need to solve.

```python  
from secret import FLAG

flag = FLAG[::-1]

new_flag = ''

for i in range(0, len(flag), 3):

new_flag += flag[i+1]  
new_flag += flag[i+2]  
new_flag += flag[i]

print(new_flag)  
```

Here's the solution script:

```python  
encoded_flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"

decoded_flag = ''  
length = len(encoded_flag)

for i in range(0, length, 3):  
decoded_flag += encoded_flag[i+2]  
decoded_flag += encoded_flag[i]  
decoded_flag += encoded_flag[i+1]

original_flag = decoded_flag[::-1]  
print(original_flag)  
```

And the flag is:

```text  
HTB{4_b3tTeR_w3apOn_i5_n3edeD!?!}  
```
