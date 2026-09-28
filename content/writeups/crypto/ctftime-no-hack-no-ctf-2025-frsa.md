---
title: "FRSA - No Hack No CTF 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "frequency-analysis", "frsa", "no-hack-no-ctf", "no-hack-no-ctf-2025", "2025", "ctf-writeup"]
summary: "At first glance, this challenge looks like an RSA problem - but in reality, it’s a monoalphabetic substitution cipher."
source:
  name: "CTFtime writeup #40448"
  url: "https://ctftime.org/writeup/40448"
ctf:
  name: "No Hack No CTF 2025"
  year: 2025
  challenge: "FRSA"
---

## Metadata

- **CTF:** No Hack No CTF 2025
- **Task:** FRSA
- **Author team:** WhiteDukesDZ
- **CTFtime:** <https://ctftime.org/writeup/40448>

---
# ? FRSA (Frequency RSA)

At first glance, this challenge looks like an **RSA** problem — but in reality, it’s a **monoalphabetic substitution** cipher.   
The script encrypts each character independently as:

`c = (ord(ch))^e mod n`

and outputs the list of residues.

Because each character is processed separately, every plaintext symbol maps to a single, fixed ciphertext value.   
In our case, the plaintext is **uppercased**, so if we take the set of distinct ciphertext integers \\(X\\), we get **27 unique symbols** — corresponding to the **26 English letters plus the space**.

\---

## ? Principle

The intended method of solving this challenge is **frequency analysis**.   
We rank the ciphertext values by how often they occur, and then map them to the expected frequency order of English characters:

```  
ETIASNHORDMFLCGUYBWKVPQZXJ  
```

(Space is the most frequent character.)

Hence the challenge’s name: **FRSA** — short for **Frequency RSA**.

\---

## ? First Result

Applying this direct frequency mapping gives the following intermediate text:

```  
AN WENEROU VHUTOARE IOAD TSAI ANODVERTENTUG O CEP CUAEI YATE O CEP TALEI NEVER MON DETOAN O SERHAM WOUUHKANW SHRIE TSAI IEELI TH LOBE O UHT HC IENIE RAWST TSE JFAMB YRHPN CHQ ZFLKI HVER TSE UOXG DHW DELHMRATFI HNME IOAD TSAI DHNT UHHB OT EVERGHNE PATS DAITRFIT YFT YE CARL OND CARL TSAI AI ANDEED O PAIE IOGANW TSEN PSOT YOWESHT HNME IOAD O CARL YEUAEC MON LOBE TSE SEORT HC TSE ITRHNW CARL OND TSEG ORE LHRE DETERLANED OUTSHFWS TSAI IENTENME AI ISHRT AT LOBEI LE TSANB OYHFT AT PSG DHEI NSNMTSAIAIRIOONDCREJFENMGONOUGIAI SOKKEN  
```

This text isn’t yet readable — the ciphertext isn’t long enough for letter frequencies to stabilize perfectly, so some mappings are still off.

\---

## ? Improving the Decryption

To refine the result, you can use online **monoalphabetic substitution solvers**:

\- ? [dCode — Monoalphabetic Substitution](<https://www.dcode.fr/substitution-monoalphabetique>)   
\- ? [quipqiup](<https://quipqiup.com/>)

These tools can use patterns and digraphs to complete the decryption automatically.

\---

## ✅ Final Plaintext

Using these tools, we recover the intended plaintext:

```  
IN GENERAL VOLTAIRE SAID THIS INADVERTENTLY A FEW FLIES BITE A FEW TIMES NEVER CAN DETAIN A HEROIC GALLOPING HORSE THIS SEEMS TO MAKE A LOT OF SENSE RIGHT THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG DEMOCRITUS ONCE SAID THIS DONT LOOK AT EVERYONE WITH DISTRUST BUT BE FIRM AND FIRM THIS IS INDEED A WISE SAYING THEN WHAT BAGEHOT ONCE SAID A FIRM BELIEF CAN MAKE THE HEART OF THE STRONG FIRM AND THEY ARE MORE DETERMINED ALTHOUGH THIS SENTENCE IS SHORT IT MAKES ME THINK ABOUT IT WHY DOES NHNCTHISISRSAANDFREQUENCYANALYSIS HAPPEN  
```

\---

## ? Flag

```  
NHNC{THIS_IS_RSA_AND_FREQUENCY_ANALYSIS}  
```

\---
