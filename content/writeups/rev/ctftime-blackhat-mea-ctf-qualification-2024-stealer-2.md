---
title: "Stealer - BlackHat MEA CTF Qualification 2024"
category: "rev"
type: "writeup"
tags: ["rev", "reversing", "forensics", "bhmea24", "cyberchef", "base64", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Hello Everyone, I will keep it short and simple :p"
source:
  name: "CTFtime writeup #39424"
  url: "https://ctftime.org/writeup/39424"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Stealer"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Stealer
- **Author team:** APT-X
- **CTFtime tags:** reversing, forensics, bhmea24
- **CTFtime:** <https://ctftime.org/writeup/39424>

---
Hello Everyone, I will keep it short and simple :p

Step 1: Upload the Provided File on Virus Total for Analysis

Step 2: Go to Cryptographic Plain Text in the Behaviour Section

You will have the following:

Cryptographical plain text

5481237002  
7267561120:QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9

Step 3: Copy the Token which is QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9

Step 4: Paste the Token in Input section of Cyberchef having the URL <https://gchq.github.io/CyberChef/>

Step 5: Use the Function "Decode from Base64"

Step 6: You will receive the following Flag:

BHFlagY{t3legr4m_g0es_w!ld}

Have Fun!
