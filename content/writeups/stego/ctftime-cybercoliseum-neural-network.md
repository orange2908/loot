---
title: "Neural network - Cybercoliseum Ⅲ"
category: "stego"
type: "writeup"
tags: ["stego", "steganography", "neural", "network", "cybercoliseum", "ctf-writeup"]
summary: "We see that one sentence is written with different case"
source:
  name: "CTFtime writeup #39120"
  url: "https://ctftime.org/writeup/39120"
original_source: "https://github.com/zer00d4y/writeups/blob/main/CTF%20events/Cybercoliseum/Cybercoliseum%20%E2%85%A2.md"
ctf:
  name: "Cybercoliseum Ⅲ"
  challenge: "Neural network"
---

## Metadata

- **CTF:** Cybercoliseum Ⅲ
- **Task:** Neural network
- **Author team:** RedNet
- **CTFtime tags:** steganography
- **CTFtime:** <https://ctftime.org/writeup/39120>
- **Original writeup:** <https://github.com/zer00d4y/writeups/blob/main/CTF%20events/Cybercoliseum/Cybercoliseum%20%E2%85%A2.md>

---
### Stego - Neural network

![task](<https://github.com/zer00d4y/writeups/assets/128820441/42ed85de-1a92-4a22-a9bb-a4f23c734489>)

We see that one sentence is written with different case

Replace small letters with A, capital letters with B

`In TexT steGaNograpHY, the SECRet MEsSage Is tYPiCallY emBdded bY making suBtIE MOdiFIcATioNs`

`BA BAAB AAABABAAAAABB AAA BBBBAA BBABAAA BA ABBABAAAB AABAAAA AB AAAAAA AABABB BBAABBABBAABA`

[Bacon Cipher decoder](<https://www.dcode.fr/bacon-cipher>)

FLAG:

CODEBY{URIGHTITISBAC?NS}
