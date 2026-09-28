---
title: "The Butterfly effect - Infobahn CTF 2025"
category: "pwn"
type: "writeup"
tags: ["v8", "pwn", "type-confusion", "xor", "butterfly", "effect", "infobahn-ctf", "infobahn-ctf-2025", "2025", "ctf-writeup"]
summary: "magic method for array is added."
source:
  name: "CTFtime writeup #40480"
  url: "https://ctftime.org/writeup/40480"
original_source: "https://deayzl.tistory.com/entry/Infobahn-CTF-2025PWNV8-The-Butterfly-effect"
ctf:
  name: "Infobahn CTF 2025"
  year: 2025
  challenge: "The Butterfly effect"
---

## Metadata

- **CTF:** Infobahn CTF 2025
- **Task:** The Butterfly effect
- **Author team:** The Amazing Digital Orange!
- **CTFtime tags:** v8, pwn, type-confusion
- **CTFtime:** <https://ctftime.org/writeup/40480>
- **Original writeup:** <https://deayzl.tistory.com/entry/Infobahn-CTF-2025PWNV8-The-Butterfly-effect>

---
magic method for array is added.  
what does magic do?  
1\. add 1 to atomic variable and check if its old value is not 0. (it means magic method can only be executed once)  
2\. the array gotta have simple elements and its kind should be PACKED_DOUBLE_ELEMENTS and its length should be 3.  
3\. get 2 arguments as array index and array bitpos, and check if at least one of them is 0. they all should not be 0.  
4\. array index <= array length and array bitpos < 64.  
5\. get array[array index] and xor bit where array bitpos value indicates.  
6\. write resultant value to array[array index].  
In short, it just flips one bit of element in double array once.  
  
The vulnerability is simple:  
```diff  
\+ if (!(arr_index <= array_length) || !(arr_bitpos < 64)) {  
\+ THROW_NEW_ERROR_RETURN_FAILURE(  
\+ isolate, NewRangeError(  
\+ MessageTemplate::kPlaceholderOnly,  
\+ factory->NewStringFromAsciiChecked(  
\+ "arguments out of range")));  
\+ }  
```  
I can pass array length as array index into magic method, then it passes.  
  
Here's PoC.  
```  
const a = [1.1, 2.2, 3.3]; // PACKED_DOUBLE_ELEMENTS  
a.magic(a.length, 0);  
%DebugPrint(a);  
```

more at <https://deayzl.tistory.com/entry/Infobahn-CTF-2025PWNV8-The-Butterfly-effect>
