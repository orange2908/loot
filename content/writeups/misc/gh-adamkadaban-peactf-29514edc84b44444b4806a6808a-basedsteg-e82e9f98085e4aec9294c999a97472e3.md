---
title: "BasedSteg e82e9f98085e4aec9294c999a97472e3 - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "misc"
subcategory: "misc"
type: "writeup"
tags: ["misc", "base64", "basedsteg", "e82e9f98085e4aec9294c999a97472e3", "miscellaneous", "basedsteg-e82e9f98085e4aec9294c999a97472"]
summary: "misc writeup for \"BasedSteg e82e9f98085e4aec9294c999a97472e3\" from PeaCTF 29514edc84b44444b4806a6808a3fc68 - techniques: base64, basedsteg, e82e9f98085e4aec9294c999a97472e3, miscellaneous, basedsteg-e"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/BasedSteg%20e82e9f98085e4aec9294c999a97472e3.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "BasedSteg e82e9f98085e4aec9294c999a97472e3"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** BasedSteg e82e9f98085e4aec9294c999a97472e3
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/BasedSteg%20e82e9f98085e4aec9294c999a97472e3.md>

---
# BasedSteg

> Steganography is the computer science of concealing or encrypting a message within a file, these are often found in ARG’s left by hackers. Find the message hidden within the image. [https://tinyurl.com/baseencryption](https://tinyurl.com/baseencryption)
No flag formatting required.

1. Download the image
2. We can see a very faint text at the bottom

    ![BasedSteg%20e82e9f98085e4aec9294c999a97472e3/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/BasedSteg%20e82e9f98085e4aec9294c999a97472e3/Untitled.png)

3. Let's increase the brightness

    ![BasedSteg%20e82e9f98085e4aec9294c999a97472e3/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/BasedSteg%20e82e9f98085e4aec9294c999a97472e3/Untitled%201.png)

4. The text says QmFzZWQgYW5kIHN0ZWdwaWxsZWQ=
    - Looks like base64... lets decode it
5. Our flag is Based and stegpilled
