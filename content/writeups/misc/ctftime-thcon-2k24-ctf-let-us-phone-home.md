---
title: "Let us Phone Home - THCon 2k24 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "let", "phone", "home", "thcon-2k24-ctf", "ctf-writeup"]
summary: "\\- In the challenge find me if you can the procedure told was connect to port 4242 with pssword 'THCON{E.T.-PH0N3-H0M3}'"
source:
  name: "CTFtime writeup #39033"
  url: "https://ctftime.org/writeup/39033"
original_source: "https://github.com/2-quantum/THCON-2k24/blob/main/let-us-phone-home/phone-home.md"
ctf:
  name: "THCon 2k24 CTF"
  challenge: "Let us Phone Home"
---

## Metadata

- **CTF:** THCon 2k24 CTF
- **Task:** Let us Phone Home
- **Author team:** Bits & Pieces
- **CTFtime:** <https://ctftime.org/writeup/39033>
- **Original writeup:** <https://github.com/2-quantum/THCON-2k24/blob/main/let-us-phone-home/phone-home.md>

---
# Let-us-Phone-Home THCON 2024

## Challenge  
![Challenge](phone-home.png)

## Solution  
\- In the challenge find me if you can the procedure told was connect to port 4242 with pssword 'THCON{E.T.-PH0N3-H0M3}'

```  
nc 20.19.38.158 4242  
```

\- After running the above command type the password i.e.  
```  
THCON{E.T.-PH0N3-H0M3}  
```  
\- After that it gave the flag and port to connect for next challenge but unfortunately i was not able to solve the next challenge.

```  
flag : THCON{I_H4V3_4_84D_F33L1NG_4B0UT_TH15}  
```
