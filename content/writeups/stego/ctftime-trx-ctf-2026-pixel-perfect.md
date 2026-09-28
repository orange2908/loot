---
title: "Pixel Perfect - TRX CTF 2026"
category: "stego"
subcategory: "file-upload"
type: "writeup"
tags: ["stego", "file-upload", "polyglot", "pixel", "perfect", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "The new version patches the simplest arbitrary-file upload RCE path."
source:
  name: "CTFtime writeup #40710"
  url: "https://ctftime.org/writeup/40710"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-pixel-perfect-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "Pixel Perfect"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** Pixel Perfect
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40710>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-pixel-perfect-writeup>

---
Summary  
The new version patches the simplest arbitrary-file upload RCE path. In the earlier version, /upload accepted a plain ELF shared object if the submitted filename ended in an allowed image extension such as .png. The exploit could then use a Python format-string bug in User.__str__() to reach ctypes.cdll[...] and dlopen() the uploaded shared object.

The patched version adds image validation to the browser upload route. A plain ELF uploaded as evil.png is now rejected because it is not a valid image. The core RCE primitive was not fixed, though. The bypass is to upload a file that is both:

a valid Linux shared object for dlopen(), and  
recognizable by Pillow as an image during validation.  
The final exploit uses an ELF + Kodak PhotoCD / PCD polyglot:

```  
offset 0: 7f 45 4c 46 # ELF header, required by dlopen()  
offset 2048: 50 43 44 5f # "PCD_", enough for Pillow's PCD detector  
That gets the malicious shared object through Pillow validation while still letting ctypes load it. Its constructor runs /readflag, writes the result into a separate uploaded holder image, and the flag is read back through /raw/<holder_code>.  
```

The complete chain is:

```  
valid holder PNG upload  
-> get holder absolute path from metadata  
compile malicious .so  
-> patch it into ELF/PCD polyglot  
upload polyglot as evil.png  
-> get evil absolute path from metadata  
register user with raw quoted-display-name email containing Python format payload  
login as that user  
-> logger stringifies User  
-> User.__str__() evaluates attacker-controlled str.format field  
-> format traversal reaches ctypes.cdll[evil_path]  
-> dlopen(evil_path)  
-> shared object constructor executes /readflag  
-> output overwrites holder upload  
fetch /raw/<holder_code>  
-> flag  
```  
No log viewer is needed. The logger is only the execution trigger.
