---
title: "TEYVAT TALES - VishwaCTF 2024"
category: "web"
type: "writeup"
tags: ["web", "teyvat", "tales", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "This is what the given web instance opens up to."
source:
  name: "CTFtime writeup #39535"
  url: "https://ctftime.org/writeup/39535"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/Teyvat%20Tales.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "TEYVAT TALES"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** TEYVAT TALES
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39535>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/Teyvat%20Tales.pdf>

---
### Solution: 

This is what the given web instance opens up to. We see 4 different types of ciphers. From the   
description it is clear that the question revolves around the languages found in the game   
Genshin Impact. 

Dcode provides decoders for all of these ciphers. Extra hint has been given to find out which   
language is which. 

The correct inputs are: 

Input 1: Enigma M3 

Input 2: UKW C 

Input 3: rotor1 i p m rotor2 iv a o rotor3 vi i n 

Input 4: vi sh wa ct fx 

On entering correct inputs, another encoded string is revealed. 

The solver must use previously decoded strings as specifications required for using Enigma   
Machine to decode the final flag string. 

<https://cryptii.com/>   
<https://www.dcode.fr/genshin-impact-languages>

Flag: 

`VishwaCTF{beware_of_tone-deaf_bard} `
