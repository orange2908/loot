---
title: "Rust - ImaginaryCTF 2024"
category: "rev"
subcategory: "rust"
type: "writeup"
tags: ["rev", "rust", "re", "imaginaryctf", "imaginaryctf-2024", "2024", "ctf-writeup"]
summary: "If we examine the rust::encrypt function, we could see that each value is independent."
source:
  name: "CTFtime writeup #39336"
  url: "https://ctftime.org/writeup/39336"
original_source: "https://github.com/Team-Kirby/ictf-2024-writeups/blob/main/re/rust/solve.py"
ctf:
  name: "ImaginaryCTF 2024"
  year: 2024
  challenge: "Rust"
---

## Metadata

- **CTF:** ImaginaryCTF 2024
- **Task:** Rust
- **Author team:** Team Kirby
- **CTFtime tags:** rust, re
- **CTFtime:** <https://ctftime.org/writeup/39336>
- **Original writeup:** <https://github.com/Team-Kirby/ictf-2024-writeups/blob/main/re/rust/solve.py>

---
If we examine the rust::encrypt function, we could see that each value is independent.  
So by figuring out key that gets us the first value, we can use the same key for the rest.  
Since we know that the flag starts with `i`, and the encrypt is a simple math equation that  
the output correspond to the key value, we can do a quick bruteforce to get the key.

Once we have the key, we can run through the rust by looping through printable and try to match the next given output.
