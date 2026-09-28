---
title: "[Blockchain] Curious Move - TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
category: "rev"
type: "writeup"
tags: ["rev", "xor", "blockchain", "curious", "move", "tcp1p-ctf-2024-exploring-nusan", "tcp1p-ctf-2024-exploring-nusantara", "2024", "ctf-writeup"]
summary: "you are a given CuriousMove.mv file which apparently is a move smart contract file."
source:
  name: "CTFtime writeup #39549"
  url: "https://ctftime.org/writeup/39549"
ctf:
  name: "TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
  year: 2024
  challenge: "[Blockchain] Curious Move"
---

## Metadata

- **CTF:** TCP1P CTF 2024: Exploring Nusantara's Digital Realm
- **Task:** [Blockchain] Curious Move
- **Author team:** xor and the half adder
- **CTFtime:** <https://ctftime.org/writeup/39549>

---
you are a given `[CuriousMove.mv](http://CuriousMove.mv)` file which apparently is a move smart contract file.  
it can be decompiled using <https://github.com/verichains/revela>

```mov  
module 0x1::CuriousMove {  
public fun xor_array() {  
let v0 = 0x1::vector::empty<u8>();  
0x1::vector::push_back<u8>(&mut v0, 99);  
0x1::vector::push_back<u8>(&mut v0, 116);  
0x1::vector::push_back<u8>(&mut v0, 103);  
0x1::vector::push_back<u8>(&mut v0, 6);  
0x1::vector::push_back<u8>(&mut v0, 103);  
0x1::vector::push_back<u8>(&mut v0, 76);  
0x1::vector::push_back<u8>(&mut v0, 86);  
0x1::vector::push_back<u8>(&mut v0, 104);  
0x1::vector::push_back<u8>(&mut v0, 84);  
0x1::vector::push_back<u8>(&mut v0, 66);  
0x1::vector::push_back<u8>(&mut v0, 69);  
0x1::vector::push_back<u8>(&mut v0, 94);  
0x1::vector::push_back<u8>(&mut v0, 88);  
0x1::vector::push_back<u8>(&mut v0, 66);  
0x1::vector::push_back<u8>(&mut v0, 68);  
0x1::vector::push_back<u8>(&mut v0, 104);  
0x1::vector::push_back<u8>(&mut v0, 64);  
0x1::vector::push_back<u8>(&mut v0, 86);  
0x1::vector::push_back<u8>(&mut v0, 89);  
0x1::vector::push_back<u8>(&mut v0, 83);  
0x1::vector::push_back<u8>(&mut v0, 82);  
0x1::vector::push_back<u8>(&mut v0, 69);  
0x1::vector::push_back<u8>(&mut v0, 82);  
0x1::vector::push_back<u8>(&mut v0, 69);  
0x1::vector::push_back<u8>(&mut v0, 104);  
0x1::vector::push_back<u8>(&mut v0, 94);  
0x1::vector::push_back<u8>(&mut v0, 67);  
0x1::vector::push_back<u8>(&mut v0, 104);  
0x1::vector::push_back<u8>(&mut v0, 68);  
0x1::vector::push_back<u8>(&mut v0, 82);  
0x1::vector::push_back<u8>(&mut v0, 82);  
0x1::vector::push_back<u8>(&mut v0, 90);  
0x1::vector::push_back<u8>(&mut v0, 68);  
0x1::vector::push_back<u8>(&mut v0, 74);  
let v1 = 0x1::vector::empty<u8>();  
let v2 = 0;  
while (v2 < 0x1::vector::length<u8>(&v0)) {  
0x1::vector::push_back<u8>(&mut v1, *0x1::vector::borrow<u8>(&v0, v2) ^ 55);  
v2 = v2 + 1;  
};  
0x1::debug::print<vector<u8>>(&v1;;  
}  
  
// decompiled from Move bytecode v6  
}  
```  
and then just convert the hex to ascii and you get the flag.
