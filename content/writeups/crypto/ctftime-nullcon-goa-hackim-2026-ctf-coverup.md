---
title: "Coverup - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "base64", "coverup", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "A PHP-based challenge where we are given encrypt.php (encryption logic), generatechallenge.php (coverage collection), coverage.json (xdebug coverage data), and encryptedflag.txt."
source:
  name: "CTFtime writeup #40584"
  url: "https://ctftime.org/writeup/40584"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Coverup"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Coverup
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40584>

---
**Challenge Description**:  
A PHP-based challenge where we are given `encrypt.php` (encryption logic), `generate_challenge.php` (coverage collection), `coverage.json` (xdebug coverage data), and `encrypted_flag.txt`.

**Analysis**:  
The encryption process involves:  
1\. **Key Transformation**: Each key character is transformed via a lookup table (`processedKeyAscii = ord(keyChar) + offset`)  
2\. **XOR Operation**: `xored = plaintext ^ processedKey`  
3\. **Final Mapping**: Each xored value is mapped to a final byte via another lookup table (`finalAscii = ord(xored) + offset`)  
4\. The result is Base64-encoded with a SHA1 checksum

The key insight is that `coverage.json` contains xdebug coverage data that reveals:  
\- **Which key character branches were executed** (tells us the 9 unique chars in the key)  
\- **Which xored value branches were executed** (tells us which xored values actually occurred during encryption)

**Solution**:

1\. **Recover Key Characters (9 unique)**:  
Parse coverage data to find which `if ($keyChar == chr(N))` assignment lines were hit:  
```  
Key chars: ['1', '=', 'A', 'D', 'V', 'l', 'o', 'p', 'z']  
```

2\. **Recover Valid Xored Values (40 values)**:  
Parse coverage data to find which `if ($xored == chr(N))` assignment lines were hit. This filters the ambiguous reverse mapping.

3\. **Determine Key Order**:  
\- First 4 bytes of flag are `ENO{`  
\- Tested which key chars produce these for positions 0-3: `=` → `E`, `p` → `N`, `V` → `O`, `z` → `{`  
\- Brute-forced remaining 5 positions (5! = 120 permutations)  
\- Found key: `=pVz1AlDo`

4\. **Decrypt**:  
Used the xored coverage filter to eliminate ambiguous decryption paths, reducing candidates from millions to just 16 valid flags.

**Solver**: [[solve.py](http://solve.py)](file:///home/mritunjya/ctf/2026/nullcon/rev/coverup/[solve.py](http://solve.py))

**Flag**: `ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}`
