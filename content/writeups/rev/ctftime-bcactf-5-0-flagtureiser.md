---
title: "Flagtureiser - BCACTF 5.0"
category: "rev"
type: "writeup"
tags: ["rev", "flagtureiser", "bcactf", "bcactf-5-0", "ctf-writeup"]
summary: "I opened the .jar file in an online java decompiler."
source:
  name: "CTFtime writeup #39267"
  url: "https://ctftime.org/writeup/39267"
original_source: "https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/rev/Flagtureiser"
ctf:
  name: "BCACTF 5.0"
  challenge: "Flagtureiser"
---

## Metadata

- **CTF:** BCACTF 5.0
- **Task:** Flagtureiser
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39267>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/rev/Flagtureiser>

---
I opened the .jar file in an online java decompiler.

Checked the flagtureiser.class and it had an array with some ascii codes.  
```  
static void _6d8f2e1fefef5b67bf4f49179b84f29f7d1e01f0() throws Exception {  
Class.forName(...new String(new byte[]{98, 99, 97, 99, 116, 102, 123, 102, 82, 97, 67, 116, 117, 114, 51, 49, 115, 51, 82, 95, 115, 84, 56, 103, 69, 95, 122, 51, 82, 48, 125})...  
}  
```

Translated them and found the flag.

![photo](<https://github.com/juke-33/Write-ups/raw/main/BCACTF%205.0/rev/Flagtureiser/Photo1.png>)

Flag: `bcactf{fRaCtur31s3R_sT8gE_z3R0}`
