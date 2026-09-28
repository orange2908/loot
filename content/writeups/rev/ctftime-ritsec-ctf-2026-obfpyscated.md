---
title: "obfpyscated - RITSEC CTF 2026"
category: "rev"
subcategory: "aes"
type: "writeup"
tags: ["rev", "deobfuscation", "python", "re", "marshal", "aes", "xor", "python-bytecode", "exec", "ritsec-ctf", "ritsec-ctf-2026", "2026", "ctf-writeup"]
summary: "We’re given a Python-based challenge with the main logic hidden in an obfuscated script (meow.py)."
source:
  name: "CTFtime writeup #40707"
  url: "https://ctftime.org/writeup/40707"
original_source: "https://ctftime.org/team/431287"
ctf:
  name: "RITSEC CTF 2026"
  year: 2026
  challenge: "obfpyscated"
---

## Metadata

- **CTF:** RITSEC CTF 2026
- **Task:** obfpyscated
- **Author team:** Echelon Obscura
- **CTFtime tags:** deobfuscation, python, re, marshal
- **CTFtime:** <https://ctftime.org/writeup/40707>
- **Original writeup:** <https://ctftime.org/team/431287>

---
### obfpyscated (Reversing) - RITSEC CTF 2026  
We’re given a Python-based challenge with the main logic hidden in an obfuscated script (`[meow.py](http://meow.py)`). At first glance, it’s clear this isn’t going to be a simple read-through.

#### Approach  
The setup includes:  
1\. A `Dockerfile` that installs `pycryptodome` and `pillow`.  
1\. A wrapper script (`[run.sh](http://run.sh)`) to build and run the container  
1\. An obfuscated Python script (`[meow.py](http://meow.py)`) that serves as the entry point

Inside `[meow.py](http://meow.py)`, the entire payload is wrapped in:  
```python  
exec(''.join(chr(_^2) for _ in <bytes>))  
```

This immediately tells us:  
1\. The script is XOR-obfuscated with key `2`.  
1\. The actual logic is only revealed at runtime via `exec`.  
1\. Static inspection requires peeling back layers manually.

After reversing the first XOR layer, the challenge unfolds into multiple stages of obfuscation, including:  
1\. AES-based decryption using `pycryptodome`.  
1\. Dynamically reconstructed values.  
1\. Python bytecode hidden using `marshal`.  
1\. Additional transformations applied at runtime (including XOR chains).  
1\. A final stage involving data encoded within an image using `pillow`.

One of the key hurdles is the use of Python’s `marshal` module, which allows serialized bytecode to be embedded and executed dynamically. This makes the payload significantly harder to analyze statically, since meaningful logic is only reconstructed during execution.

Each stage reveals just enough information to proceed, forcing a **step-by-step reconstruction** of the entire execution flow rather than allowing direct access to the final logic.

#### Solution  
Multi-layered obfuscation with marshal and runtime decoding makes this one lengthy to fully break down. The solution involves peeling back several layers of Python bytecode and transformations, so it’s not practical to summarize briefly here. For a full step-by-step breakdown and reversing details, I wrote a detailed post [here](<https://pnasis.gitlab.io/posts/ritsec-ctf-2026-reversing-writeups-part-4-obfpyscated/>) ;).

#### Flag  
```bash  
$ python [get-flag.py](http://get-flag.py)  
RS{1f_y0u_r4n_th47_0n_y0ur_h0s7_y0u_sh0uld_m4k3_b3tter_d3cis1on5}  
```

#### Notes  
A key part of solving this challenge was using the provided `Dockerfile` to replicate the intended environment and safely observe the runtime behavior.

The core idea revolves around reversing Python marshal bytecode hidden behind multiple layers of obfuscation.
